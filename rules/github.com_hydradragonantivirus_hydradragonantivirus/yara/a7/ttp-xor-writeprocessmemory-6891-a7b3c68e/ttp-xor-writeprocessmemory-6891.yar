rule TTP_XOR_WriteProcessMemory_6891 {
  strings:
    $key_6891 = { 3f e3 [2] 0d c1 [2] 0b f4 [2] 25 f4 [2] 1a e8 }

  condition:
    any of them
}