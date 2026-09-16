rule TTP_XOR_WriteProcessMemory_0189 {
  strings:
    $key_0189 = { 56 fb [2] 64 d9 [2] 62 ec [2] 4c ec [2] 73 f0 }

  condition:
    any of them
}