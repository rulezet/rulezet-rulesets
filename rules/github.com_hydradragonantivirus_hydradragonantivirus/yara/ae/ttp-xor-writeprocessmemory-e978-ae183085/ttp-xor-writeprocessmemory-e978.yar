rule TTP_XOR_WriteProcessMemory_e978 {
  strings:
    $key_e978 = { be 0a [2] 8c 28 [2] 8a 1d [2] a4 1d [2] 9b 01 }

  condition:
    any of them
}