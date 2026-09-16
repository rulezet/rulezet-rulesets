rule TTP_XOR_WriteProcessMemory_e0c7 {
  strings:
    $key_e0c7 = { b7 b5 [2] 85 97 [2] 83 a2 [2] ad a2 [2] 92 be }

  condition:
    any of them
}