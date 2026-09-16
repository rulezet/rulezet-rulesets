rule TTP_XOR_WriteProcessMemory_3789 {
  strings:
    $key_3789 = { 60 fb [2] 52 d9 [2] 54 ec [2] 7a ec [2] 45 f0 }

  condition:
    any of them
}