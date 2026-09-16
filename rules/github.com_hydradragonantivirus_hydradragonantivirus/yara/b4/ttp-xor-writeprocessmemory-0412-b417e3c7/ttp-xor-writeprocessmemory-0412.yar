rule TTP_XOR_WriteProcessMemory_0412 {
  strings:
    $key_0412 = { 53 60 [2] 61 42 [2] 67 77 [2] 49 77 [2] 76 6b }

  condition:
    any of them
}