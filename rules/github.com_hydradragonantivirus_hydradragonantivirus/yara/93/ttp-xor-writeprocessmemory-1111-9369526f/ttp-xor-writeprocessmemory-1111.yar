rule TTP_XOR_WriteProcessMemory_1111 {
  strings:
    $key_1111 = { 46 63 [2] 74 41 [2] 72 74 [2] 5c 74 [2] 63 68 }

  condition:
    any of them
}