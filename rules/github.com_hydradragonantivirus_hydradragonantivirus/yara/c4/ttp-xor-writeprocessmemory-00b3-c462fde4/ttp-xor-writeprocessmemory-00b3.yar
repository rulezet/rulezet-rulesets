rule TTP_XOR_WriteProcessMemory_00b3 {
  strings:
    $key_00b3 = { 57 c1 [2] 65 e3 [2] 63 d6 [2] 4d d6 [2] 72 ca }

  condition:
    any of them
}