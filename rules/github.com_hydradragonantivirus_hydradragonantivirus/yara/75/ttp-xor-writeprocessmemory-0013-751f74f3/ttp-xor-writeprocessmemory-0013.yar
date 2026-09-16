rule TTP_XOR_WriteProcessMemory_0013 {
  strings:
    $key_0013 = { 57 61 [2] 65 43 [2] 63 76 [2] 4d 76 [2] 72 6a }

  condition:
    any of them
}