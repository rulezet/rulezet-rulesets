rule TTP_XOR_WriteProcessMemory_76cc {
  strings:
    $key_76cc = { 21 be [2] 13 9c [2] 15 a9 [2] 3b a9 [2] 04 b5 }

  condition:
    any of them
}