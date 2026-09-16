rule TTP_XOR_WriteProcessMemory_31b3 {
  strings:
    $key_31b3 = { 66 c1 [2] 54 e3 [2] 52 d6 [2] 7c d6 [2] 43 ca }

  condition:
    any of them
}