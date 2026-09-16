rule TTP_XOR_WriteProcessMemory_86a8 {
  strings:
    $key_86a8 = { d1 da [2] e3 f8 [2] e5 cd [2] cb cd [2] f4 d1 }

  condition:
    any of them
}