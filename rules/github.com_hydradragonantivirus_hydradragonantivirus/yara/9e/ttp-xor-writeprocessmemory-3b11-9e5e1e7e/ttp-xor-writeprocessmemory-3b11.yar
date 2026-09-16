rule TTP_XOR_WriteProcessMemory_3b11 {
  strings:
    $key_3b11 = { 6c 63 [2] 5e 41 [2] 58 74 [2] 76 74 [2] 49 68 }

  condition:
    any of them
}