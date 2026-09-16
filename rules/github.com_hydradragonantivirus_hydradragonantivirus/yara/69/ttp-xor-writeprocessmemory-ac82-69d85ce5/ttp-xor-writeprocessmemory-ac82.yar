rule TTP_XOR_WriteProcessMemory_ac82 {
  strings:
    $key_ac82 = { fb f0 [2] c9 d2 [2] cf e7 [2] e1 e7 [2] de fb }

  condition:
    any of them
}