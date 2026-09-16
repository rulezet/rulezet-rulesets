rule TTP_XOR_WriteProcessMemory_cfa4 {
  strings:
    $key_cfa4 = { 98 d6 [2] aa f4 [2] ac c1 [2] 82 c1 [2] bd dd }

  condition:
    any of them
}