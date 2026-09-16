rule TTP_XOR_WriteProcessMemory_76b3 {
  strings:
    $key_76b3 = { 21 c1 [2] 13 e3 [2] 15 d6 [2] 3b d6 [2] 04 ca }

  condition:
    any of them
}