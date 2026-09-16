rule TTP_XOR_WriteProcessMemory_ad8c {
  strings:
    $key_ad8c = { fa fe [2] c8 dc [2] ce e9 [2] e0 e9 [2] df f5 }

  condition:
    any of them
}