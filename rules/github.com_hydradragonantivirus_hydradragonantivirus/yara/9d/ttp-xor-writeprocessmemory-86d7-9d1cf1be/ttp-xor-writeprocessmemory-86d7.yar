rule TTP_XOR_WriteProcessMemory_86d7 {
  strings:
    $key_86d7 = { d1 a5 [2] e3 87 [2] e5 b2 [2] cb b2 [2] f4 ae }

  condition:
    any of them
}