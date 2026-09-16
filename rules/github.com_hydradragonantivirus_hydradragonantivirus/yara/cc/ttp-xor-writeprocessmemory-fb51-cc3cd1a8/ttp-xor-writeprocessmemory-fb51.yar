rule TTP_XOR_WriteProcessMemory_fb51 {
  strings:
    $key_fb51 = { ac 23 [2] 9e 01 [2] 98 34 [2] b6 34 [2] 89 28 }

  condition:
    any of them
}