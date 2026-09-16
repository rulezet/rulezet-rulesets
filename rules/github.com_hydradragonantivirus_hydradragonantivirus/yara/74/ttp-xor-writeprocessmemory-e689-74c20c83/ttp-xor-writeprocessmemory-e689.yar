rule TTP_XOR_WriteProcessMemory_e689 {
  strings:
    $key_e689 = { b1 fb [2] 83 d9 [2] 85 ec [2] ab ec [2] 94 f0 }

  condition:
    any of them
}