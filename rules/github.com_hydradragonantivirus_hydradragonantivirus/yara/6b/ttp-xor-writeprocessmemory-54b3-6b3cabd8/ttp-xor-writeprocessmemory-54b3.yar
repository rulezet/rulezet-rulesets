rule TTP_XOR_WriteProcessMemory_54b3 {
  strings:
    $key_54b3 = { 03 c1 [2] 31 e3 [2] 37 d6 [2] 19 d6 [2] 26 ca }

  condition:
    any of them
}