rule TTP_XOR_WriteProcessMemory_3ab3 {
  strings:
    $key_3ab3 = { 6d c1 [2] 5f e3 [2] 59 d6 [2] 77 d6 [2] 48 ca }

  condition:
    any of them
}