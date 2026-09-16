rule TTP_XOR_WriteProcessMemory_3331 {
  strings:
    $key_3331 = { 64 43 [2] 56 61 [2] 50 54 [2] 7e 54 [2] 41 48 }

  condition:
    any of them
}