rule TTP_XOR_WriteProcessMemory_4908 {
  strings:
    $key_4908 = { 1e 7a [2] 2c 58 [2] 2a 6d [2] 04 6d [2] 3b 71 }

  condition:
    any of them
}