rule TTP_XOR_WriteProcessMemory_e9a9 {
  strings:
    $key_e9a9 = { be db [2] 8c f9 [2] 8a cc [2] a4 cc [2] 9b d0 }

  condition:
    any of them
}