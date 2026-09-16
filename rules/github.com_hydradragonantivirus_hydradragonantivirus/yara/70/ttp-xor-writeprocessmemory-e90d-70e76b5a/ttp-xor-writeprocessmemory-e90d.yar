rule TTP_XOR_WriteProcessMemory_e90d {
  strings:
    $key_e90d = { be 7f [2] 8c 5d [2] 8a 68 [2] a4 68 [2] 9b 74 }

  condition:
    any of them
}