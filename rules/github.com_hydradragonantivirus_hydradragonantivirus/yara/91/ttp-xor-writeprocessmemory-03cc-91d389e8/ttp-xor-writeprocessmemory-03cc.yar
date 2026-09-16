rule TTP_XOR_WriteProcessMemory_03cc {
  strings:
    $key_03cc = { 54 be [2] 66 9c [2] 60 a9 [2] 4e a9 [2] 71 b5 }

  condition:
    any of them
}