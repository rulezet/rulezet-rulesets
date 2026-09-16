rule TTP_XOR_WriteProcessMemory_0566 {
  strings:
    $key_0566 = { 52 14 [2] 60 36 [2] 66 03 [2] 48 03 [2] 77 1f }

  condition:
    any of them
}