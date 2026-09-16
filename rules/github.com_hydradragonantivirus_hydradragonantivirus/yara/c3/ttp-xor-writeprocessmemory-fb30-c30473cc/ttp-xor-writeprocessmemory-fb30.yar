rule TTP_XOR_WriteProcessMemory_fb30 {
  strings:
    $key_fb30 = { ac 42 [2] 9e 60 [2] 98 55 [2] b6 55 [2] 89 49 }

  condition:
    any of them
}