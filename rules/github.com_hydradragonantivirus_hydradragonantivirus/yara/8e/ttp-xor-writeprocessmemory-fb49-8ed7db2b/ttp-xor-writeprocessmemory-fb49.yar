rule TTP_XOR_WriteProcessMemory_fb49 {
  strings:
    $key_fb49 = { ac 3b [2] 9e 19 [2] 98 2c [2] b6 2c [2] 89 30 }

  condition:
    any of them
}