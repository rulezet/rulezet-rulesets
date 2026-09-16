rule TTP_XOR_WriteProcessMemory_55cc {
  strings:
    $key_55cc = { 02 be [2] 30 9c [2] 36 a9 [2] 18 a9 [2] 27 b5 }

  condition:
    any of them
}