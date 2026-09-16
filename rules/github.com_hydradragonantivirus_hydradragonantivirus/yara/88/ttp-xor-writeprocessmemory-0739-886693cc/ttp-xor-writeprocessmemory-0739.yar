rule TTP_XOR_WriteProcessMemory_0739 {
  strings:
    $key_0739 = { 50 4b [2] 62 69 [2] 64 5c [2] 4a 5c [2] 75 40 }

  condition:
    any of them
}