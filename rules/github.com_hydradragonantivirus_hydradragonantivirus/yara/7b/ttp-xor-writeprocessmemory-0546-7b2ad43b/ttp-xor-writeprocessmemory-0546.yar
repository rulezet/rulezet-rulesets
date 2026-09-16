rule TTP_XOR_WriteProcessMemory_0546 {
  strings:
    $key_0546 = { 52 34 [2] 60 16 [2] 66 23 [2] 48 23 [2] 77 3f }

  condition:
    any of them
}