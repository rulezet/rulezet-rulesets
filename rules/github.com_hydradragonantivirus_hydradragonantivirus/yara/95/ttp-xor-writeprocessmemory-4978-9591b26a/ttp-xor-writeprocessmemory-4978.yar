rule TTP_XOR_WriteProcessMemory_4978 {
  strings:
    $key_4978 = { 1e 0a [2] 2c 28 [2] 2a 1d [2] 04 1d [2] 3b 01 }

  condition:
    any of them
}