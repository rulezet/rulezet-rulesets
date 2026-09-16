rule TTP_XOR_WriteProcessMemory_66b3 {
  strings:
    $key_66b3 = { 31 c1 [2] 03 e3 [2] 05 d6 [2] 2b d6 [2] 14 ca }

  condition:
    any of them
}