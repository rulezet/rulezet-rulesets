rule TTP_XOR_WriteProcessMemory_e97f {
  strings:
    $key_e97f = { be 0d [2] 8c 2f [2] 8a 1a [2] a4 1a [2] 9b 06 }

  condition:
    any of them
}