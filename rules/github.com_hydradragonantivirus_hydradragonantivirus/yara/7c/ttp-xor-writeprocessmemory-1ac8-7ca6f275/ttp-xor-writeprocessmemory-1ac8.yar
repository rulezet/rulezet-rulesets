rule TTP_XOR_WriteProcessMemory_1ac8 {
  strings:
    $key_1ac8 = { 4d ba [2] 7f 98 [2] 79 ad [2] 57 ad [2] 68 b1 }

  condition:
    any of them
}