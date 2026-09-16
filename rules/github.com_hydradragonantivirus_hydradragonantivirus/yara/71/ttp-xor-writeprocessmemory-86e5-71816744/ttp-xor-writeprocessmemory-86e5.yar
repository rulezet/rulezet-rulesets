rule TTP_XOR_WriteProcessMemory_86e5 {
  strings:
    $key_86e5 = { d1 97 [2] e3 b5 [2] e5 80 [2] cb 80 [2] f4 9c }

  condition:
    any of them
}