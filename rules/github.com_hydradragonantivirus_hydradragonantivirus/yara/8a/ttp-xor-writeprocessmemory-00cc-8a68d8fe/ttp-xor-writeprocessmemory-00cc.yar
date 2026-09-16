rule TTP_XOR_WriteProcessMemory_00cc {
  strings:
    $key_00cc = { 57 be [2] 65 9c [2] 63 a9 [2] 4d a9 [2] 72 b5 }

  condition:
    any of them
}