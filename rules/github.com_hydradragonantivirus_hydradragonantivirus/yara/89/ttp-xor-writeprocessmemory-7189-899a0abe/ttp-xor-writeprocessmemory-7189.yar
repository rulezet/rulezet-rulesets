rule TTP_XOR_WriteProcessMemory_7189 {
  strings:
    $key_7189 = { 26 fb [2] 14 d9 [2] 12 ec [2] 3c ec [2] 03 f0 }

  condition:
    any of them
}