rule TTP_XOR_WriteProcessMemory_34cc {
  strings:
    $key_34cc = { 63 be [2] 51 9c [2] 57 a9 [2] 79 a9 [2] 46 b5 }

  condition:
    any of them
}