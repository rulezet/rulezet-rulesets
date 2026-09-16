rule TTP_XOR_WriteProcessMemory_0017 {
  strings:
    $key_0017 = { 57 65 [2] 65 47 [2] 63 72 [2] 4d 72 [2] 72 6e }

  condition:
    any of them
}