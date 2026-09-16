rule TTP_XOR_WriteProcessMemory_0031 {
  strings:
    $key_0031 = { 57 43 [2] 65 61 [2] 63 54 [2] 4d 54 [2] 72 48 }

  condition:
    any of them
}