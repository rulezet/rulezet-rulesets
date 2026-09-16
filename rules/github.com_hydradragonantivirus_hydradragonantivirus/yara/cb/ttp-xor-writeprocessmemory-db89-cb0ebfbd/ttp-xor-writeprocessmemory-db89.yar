rule TTP_XOR_WriteProcessMemory_db89 {
  strings:
    $key_db89 = { 8c fb [2] be d9 [2] b8 ec [2] 96 ec [2] a9 f0 }

  condition:
    any of them
}