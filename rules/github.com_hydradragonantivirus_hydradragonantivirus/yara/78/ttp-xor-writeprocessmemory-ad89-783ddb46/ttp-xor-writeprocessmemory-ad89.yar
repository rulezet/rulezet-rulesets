rule TTP_XOR_WriteProcessMemory_ad89 {
  strings:
    $key_ad89 = { fa fb [2] c8 d9 [2] ce ec [2] e0 ec [2] df f0 }

  condition:
    any of them
}