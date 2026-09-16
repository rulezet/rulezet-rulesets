rule TTP_XOR_WriteProcessMemory_94d7 {
  strings:
    $key_94d7 = { c3 a5 [2] f1 87 [2] f7 b2 [2] d9 b2 [2] e6 ae }

  condition:
    any of them
}