rule TTP_XOR_WriteProcessMemory_02b3 {
  strings:
    $key_02b3 = { 55 c1 [2] 67 e3 [2] 61 d6 [2] 4f d6 [2] 70 ca }

  condition:
    any of them
}