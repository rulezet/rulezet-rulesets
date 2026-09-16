rule TTP_XOR_WriteProcessMemory_e90f {
  strings:
    $key_e90f = { be 7d [2] 8c 5f [2] 8a 6a [2] a4 6a [2] 9b 76 }

  condition:
    any of them
}