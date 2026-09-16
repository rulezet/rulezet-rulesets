rule TTP_XOR_WriteProcessMemory_86b5 {
  strings:
    $key_86b5 = { d1 c7 [2] e3 e5 [2] e5 d0 [2] cb d0 [2] f4 cc }

  condition:
    any of them
}