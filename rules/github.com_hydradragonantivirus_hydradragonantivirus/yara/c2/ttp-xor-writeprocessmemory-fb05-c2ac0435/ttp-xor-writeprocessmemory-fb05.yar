rule TTP_XOR_WriteProcessMemory_fb05 {
  strings:
    $key_fb05 = { ac 77 [2] 9e 55 [2] 98 60 [2] b6 60 [2] 89 7c }

  condition:
    any of them
}