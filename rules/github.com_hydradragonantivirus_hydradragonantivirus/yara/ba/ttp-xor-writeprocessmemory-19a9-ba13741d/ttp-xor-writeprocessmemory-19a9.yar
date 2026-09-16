rule TTP_XOR_WriteProcessMemory_19a9 {
  strings:
    $key_19a9 = { 4e db [2] 7c f9 [2] 7a cc [2] 54 cc [2] 6b d0 }

  condition:
    any of them
}