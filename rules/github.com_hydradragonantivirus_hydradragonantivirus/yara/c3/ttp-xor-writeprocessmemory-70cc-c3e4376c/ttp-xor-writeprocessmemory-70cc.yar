rule TTP_XOR_WriteProcessMemory_70cc {
  strings:
    $key_70cc = { 27 be [2] 15 9c [2] 13 a9 [2] 3d a9 [2] 02 b5 }

  condition:
    any of them
}