rule TTP_XOR_WriteProcessMemory_3ab2 {
  strings:
    $key_3ab2 = { 6d c0 [2] 5f e2 [2] 59 d7 [2] 77 d7 [2] 48 cb }

  condition:
    any of them
}