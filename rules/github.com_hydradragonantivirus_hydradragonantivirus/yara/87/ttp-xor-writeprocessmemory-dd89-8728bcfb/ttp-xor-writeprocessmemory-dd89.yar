rule TTP_XOR_WriteProcessMemory_dd89 {
  strings:
    $key_dd89 = { 8a fb [2] b8 d9 [2] be ec [2] 90 ec [2] af f0 }

  condition:
    any of them
}