rule TTP_XOR_WriteProcessMemory_5489 {
  strings:
    $key_5489 = { 03 fb [2] 31 d9 [2] 37 ec [2] 19 ec [2] 26 f0 }

  condition:
    any of them
}