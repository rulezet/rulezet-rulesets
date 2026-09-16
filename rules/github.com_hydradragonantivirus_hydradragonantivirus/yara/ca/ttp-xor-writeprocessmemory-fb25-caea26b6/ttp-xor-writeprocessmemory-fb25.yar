rule TTP_XOR_WriteProcessMemory_fb25 {
  strings:
    $key_fb25 = { ac 57 [2] 9e 75 [2] 98 40 [2] b6 40 [2] 89 5c }

  condition:
    any of them
}