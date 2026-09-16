rule TTP_XOR_WriteProcessMemory_8687 {
  strings:
    $key_8687 = { d1 f5 [2] e3 d7 [2] e5 e2 [2] cb e2 [2] f4 fe }

  condition:
    any of them
}