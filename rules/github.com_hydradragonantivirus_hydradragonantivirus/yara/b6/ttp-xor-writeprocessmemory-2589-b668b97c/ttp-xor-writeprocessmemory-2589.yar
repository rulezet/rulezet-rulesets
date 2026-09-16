rule TTP_XOR_WriteProcessMemory_2589 {
  strings:
    $key_2589 = { 72 fb [2] 40 d9 [2] 46 ec [2] 68 ec [2] 57 f0 }

  condition:
    any of them
}