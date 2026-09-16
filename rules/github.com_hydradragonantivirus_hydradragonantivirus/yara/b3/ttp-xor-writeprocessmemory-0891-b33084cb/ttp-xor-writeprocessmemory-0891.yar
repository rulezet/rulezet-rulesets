rule TTP_XOR_WriteProcessMemory_0891 {
  strings:
    $key_0891 = { 5f e3 [2] 6d c1 [2] 6b f4 [2] 45 f4 [2] 7a e8 }

  condition:
    any of them
}