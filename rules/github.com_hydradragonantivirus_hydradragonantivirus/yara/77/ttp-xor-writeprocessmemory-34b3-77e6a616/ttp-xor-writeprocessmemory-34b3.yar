rule TTP_XOR_WriteProcessMemory_34b3 {
  strings:
    $key_34b3 = { 63 c1 [2] 51 e3 [2] 57 d6 [2] 79 d6 [2] 46 ca }

  condition:
    any of them
}