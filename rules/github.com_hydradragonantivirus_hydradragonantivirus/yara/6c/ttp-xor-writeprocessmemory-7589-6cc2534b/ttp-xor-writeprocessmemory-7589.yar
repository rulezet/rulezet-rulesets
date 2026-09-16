rule TTP_XOR_WriteProcessMemory_7589 {
  strings:
    $key_7589 = { 22 fb [2] 10 d9 [2] 16 ec [2] 38 ec [2] 07 f0 }

  condition:
    any of them
}