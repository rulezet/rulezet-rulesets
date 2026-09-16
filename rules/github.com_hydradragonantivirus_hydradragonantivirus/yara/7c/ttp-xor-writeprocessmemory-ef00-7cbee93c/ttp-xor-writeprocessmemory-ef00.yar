rule TTP_XOR_WriteProcessMemory_ef00 {
  strings:
    $key_ef00 = { b8 72 [2] 8a 50 [2] 8c 65 [2] a2 65 [2] 9d 79 }

  condition:
    any of them
}