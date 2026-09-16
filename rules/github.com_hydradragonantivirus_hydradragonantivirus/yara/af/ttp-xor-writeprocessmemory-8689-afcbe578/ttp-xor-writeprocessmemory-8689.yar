rule TTP_XOR_WriteProcessMemory_8689 {
  strings:
    $key_8689 = { d1 fb [2] e3 d9 [2] e5 ec [2] cb ec [2] f4 f0 }

  condition:
    any of them
}