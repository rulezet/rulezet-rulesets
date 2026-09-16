rule TTP_XOR_WriteProcessMemory_e918 {
  strings:
    $key_e918 = { be 6a [2] 8c 48 [2] 8a 7d [2] a4 7d [2] 9b 61 }

  condition:
    any of them
}