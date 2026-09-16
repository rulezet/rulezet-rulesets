rule TTP_XOR_WriteProcessMemory_e93d {
  strings:
    $key_e93d = { be 4f [2] 8c 6d [2] 8a 58 [2] a4 58 [2] 9b 44 }

  condition:
    any of them
}