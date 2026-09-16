rule TTP_XOR_WriteProcessMemory_36cc {
  strings:
    $key_36cc = { 61 be [2] 53 9c [2] 55 a9 [2] 7b a9 [2] 44 b5 }

  condition:
    any of them
}