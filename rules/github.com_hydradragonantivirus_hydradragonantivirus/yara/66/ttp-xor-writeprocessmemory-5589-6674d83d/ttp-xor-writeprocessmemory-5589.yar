rule TTP_XOR_WriteProcessMemory_5589 {
  strings:
    $key_5589 = { 02 fb [2] 30 d9 [2] 36 ec [2] 18 ec [2] 27 f0 }

  condition:
    any of them
}