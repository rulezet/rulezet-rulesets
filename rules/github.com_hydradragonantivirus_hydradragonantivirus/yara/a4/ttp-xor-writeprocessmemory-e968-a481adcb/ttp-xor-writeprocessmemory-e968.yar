rule TTP_XOR_WriteProcessMemory_e968 {
  strings:
    $key_e968 = { be 1a [2] 8c 38 [2] 8a 0d [2] a4 0d [2] 9b 11 }

  condition:
    any of them
}