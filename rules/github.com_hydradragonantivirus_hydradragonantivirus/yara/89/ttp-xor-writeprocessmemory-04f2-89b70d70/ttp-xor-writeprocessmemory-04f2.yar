rule TTP_XOR_WriteProcessMemory_04f2 {
  strings:
    $key_04f2 = { 53 80 [2] 61 a2 [2] 67 97 [2] 49 97 [2] 76 8b }

  condition:
    any of them
}