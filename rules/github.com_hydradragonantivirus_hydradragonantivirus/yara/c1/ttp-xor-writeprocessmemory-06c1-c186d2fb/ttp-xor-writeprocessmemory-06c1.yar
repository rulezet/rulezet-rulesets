rule TTP_XOR_WriteProcessMemory_06c1 {
  strings:
    $key_06c1 = { 51 b3 [2] 63 91 [2] 65 a4 [2] 4b a4 [2] 74 b8 }

  condition:
    any of them
}