rule TTP_XOR_WriteProcessMemory_08cc {
  strings:
    $key_08cc = { 5f be [2] 6d 9c [2] 6b a9 [2] 45 a9 [2] 7a b5 }

  condition:
    any of them
}