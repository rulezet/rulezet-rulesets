rule TTP_XOR_WriteProcessMemory_04e0 {
  strings:
    $key_04e0 = { 53 92 [2] 61 b0 [2] 67 85 [2] 49 85 [2] 76 99 }

  condition:
    any of them
}