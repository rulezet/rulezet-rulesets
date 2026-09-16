rule TTP_XOR_WriteProcessMemory_0077 {
  strings:
    $key_0077 = { 57 05 [2] 65 27 [2] 63 12 [2] 4d 12 [2] 72 0e }

  condition:
    any of them
}