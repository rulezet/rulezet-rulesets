rule TTP_XOR_WriteProcessMemory_0788 {
  strings:
    $key_0788 = { 50 fa [2] 62 d8 [2] 64 ed [2] 4a ed [2] 75 f1 }

  condition:
    any of them
}