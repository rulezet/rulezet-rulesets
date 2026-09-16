rule TTP_XOR_WriteProcessMemory_233d {
  strings:
    $key_233d = { 74 4f [2] 46 6d [2] 40 58 [2] 6e 58 [2] 51 44 }

  condition:
    any of them
}