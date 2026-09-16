rule TTP_XOR_WriteProcessMemory_2889 {
  strings:
    $key_2889 = { 7f fb [2] 4d d9 [2] 4b ec [2] 65 ec [2] 5a f0 }

  condition:
    any of them
}