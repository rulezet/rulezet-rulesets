rule TTP_XOR_WriteProcessMemory_35b3 {
  strings:
    $key_35b3 = { 62 c1 [2] 50 e3 [2] 56 d6 [2] 78 d6 [2] 47 ca }

  condition:
    any of them
}