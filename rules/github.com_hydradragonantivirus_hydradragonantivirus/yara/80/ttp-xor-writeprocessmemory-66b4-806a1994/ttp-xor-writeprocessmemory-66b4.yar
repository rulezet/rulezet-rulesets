rule TTP_XOR_WriteProcessMemory_66b4 {
  strings:
    $key_66b4 = { 31 c6 [2] 03 e4 [2] 05 d1 [2] 2b d1 [2] 14 cd }

  condition:
    any of them
}