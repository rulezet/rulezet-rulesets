rule TTP_XOR_WriteProcessMemory_2c08 {
  strings:
    $key_2c08 = { 7b 7a [2] 49 58 [2] 4f 6d [2] 61 6d [2] 5e 71 }

  condition:
    any of them
}