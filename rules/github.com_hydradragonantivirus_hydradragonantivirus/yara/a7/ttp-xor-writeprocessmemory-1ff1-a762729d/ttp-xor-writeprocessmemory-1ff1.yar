rule TTP_XOR_WriteProcessMemory_1ff1 {
  strings:
    $key_1ff1 = { 48 83 [2] 7a a1 [2] 7c 94 [2] 52 94 [2] 6d 88 }

  condition:
    any of them
}