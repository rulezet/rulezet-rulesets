rule TTP_XOR_WriteProcessMemory_64ce {
  strings:
    $key_64ce = { 33 bc [2] 01 9e [2] 07 ab [2] 29 ab [2] 16 b7 }

  condition:
    any of them
}