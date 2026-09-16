rule TTP_XOR_WriteProcessMemory_7f31 {
  strings:
    $key_7f31 = { 28 43 [2] 1a 61 [2] 1c 54 [2] 32 54 [2] 0d 48 }

  condition:
    any of them
}