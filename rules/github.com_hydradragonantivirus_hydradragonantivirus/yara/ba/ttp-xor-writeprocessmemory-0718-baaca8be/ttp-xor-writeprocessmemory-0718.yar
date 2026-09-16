rule TTP_XOR_WriteProcessMemory_0718 {
  strings:
    $key_0718 = { 50 6a [2] 62 48 [2] 64 7d [2] 4a 7d [2] 75 61 }

  condition:
    any of them
}