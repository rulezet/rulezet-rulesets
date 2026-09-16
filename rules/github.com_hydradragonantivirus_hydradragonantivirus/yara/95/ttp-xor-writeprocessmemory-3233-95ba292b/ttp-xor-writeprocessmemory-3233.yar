rule TTP_XOR_WriteProcessMemory_3233 {
  strings:
    $key_3233 = { 65 41 [2] 57 63 [2] 51 56 [2] 7f 56 [2] 40 4a }

  condition:
    any of them
}