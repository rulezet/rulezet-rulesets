rule TTP_XOR_WriteProcessMemory_e91f {
  strings:
    $key_e91f = { be 6d [2] 8c 4f [2] 8a 7a [2] a4 7a [2] 9b 66 }

  condition:
    any of them
}