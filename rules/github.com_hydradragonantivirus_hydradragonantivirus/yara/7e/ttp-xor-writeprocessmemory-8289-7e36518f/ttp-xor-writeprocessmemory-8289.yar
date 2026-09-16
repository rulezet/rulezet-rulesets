rule TTP_XOR_WriteProcessMemory_8289 {
  strings:
    $key_8289 = { d5 fb [2] e7 d9 [2] e1 ec [2] cf ec [2] f0 f0 }

  condition:
    any of them
}