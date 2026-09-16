rule TTP_XOR_WriteProcessMemory_6b11 {
  strings:
    $key_6b11 = { 3c 63 [2] 0e 41 [2] 08 74 [2] 26 74 [2] 19 68 }

  condition:
    any of them
}