rule TTP_XOR_WriteProcessMemory_e09c {
  strings:
    $key_e09c = { b7 ee [2] 85 cc [2] 83 f9 [2] ad f9 [2] 92 e5 }

  condition:
    any of them
}