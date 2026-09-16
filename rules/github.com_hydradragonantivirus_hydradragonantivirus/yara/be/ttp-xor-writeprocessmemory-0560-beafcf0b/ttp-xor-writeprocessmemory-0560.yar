rule TTP_XOR_WriteProcessMemory_0560 {
  strings:
    $key_0560 = { 52 12 [2] 60 30 [2] 66 05 [2] 48 05 [2] 77 19 }

  condition:
    any of them
}