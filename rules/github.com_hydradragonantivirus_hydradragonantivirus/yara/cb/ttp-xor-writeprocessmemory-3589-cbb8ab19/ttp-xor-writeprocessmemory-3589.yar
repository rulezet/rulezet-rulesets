rule TTP_XOR_WriteProcessMemory_3589 {
  strings:
    $key_3589 = { 62 fb [2] 50 d9 [2] 56 ec [2] 78 ec [2] 47 f0 }

  condition:
    any of them
}