rule TTP_XOR_WriteProcessMemory_86e3 {
  strings:
    $key_86e3 = { d1 91 [2] e3 b3 [2] e5 86 [2] cb 86 [2] f4 9a }

  condition:
    any of them
}