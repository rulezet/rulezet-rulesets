rule TTP_XOR_WriteProcessMemory_e589 {
  strings:
    $key_e589 = { b2 fb [2] 80 d9 [2] 86 ec [2] a8 ec [2] 97 f0 }

  condition:
    any of them
}