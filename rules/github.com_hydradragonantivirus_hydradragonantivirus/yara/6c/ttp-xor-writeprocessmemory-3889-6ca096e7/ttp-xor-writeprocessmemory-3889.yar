rule TTP_XOR_WriteProcessMemory_3889 {
  strings:
    $key_3889 = { 6f fb [2] 5d d9 [2] 5b ec [2] 75 ec [2] 4a f0 }

  condition:
    any of them
}