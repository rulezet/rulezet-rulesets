rule TTP_XOR_WriteProcessMemory_cf89 {
  strings:
    $key_cf89 = { 98 fb [2] aa d9 [2] ac ec [2] 82 ec [2] bd f0 }

  condition:
    any of them
}