rule TTP_XOR_WriteProcessMemory_0536 {
  strings:
    $key_0536 = { 52 44 [2] 60 66 [2] 66 53 [2] 48 53 [2] 77 4f }

  condition:
    any of them
}