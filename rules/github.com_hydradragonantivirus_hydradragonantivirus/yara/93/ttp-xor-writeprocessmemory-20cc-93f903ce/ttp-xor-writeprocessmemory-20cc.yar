rule TTP_XOR_WriteProcessMemory_20cc {
  strings:
    $key_20cc = { 77 be [2] 45 9c [2] 43 a9 [2] 6d a9 [2] 52 b5 }

  condition:
    any of them
}