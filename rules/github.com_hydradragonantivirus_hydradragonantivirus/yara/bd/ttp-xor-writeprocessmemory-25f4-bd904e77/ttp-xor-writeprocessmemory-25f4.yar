rule TTP_XOR_WriteProcessMemory_25f4 {
  strings:
    $key_25f4 = { 72 86 [2] 40 a4 [2] 46 91 [2] 68 91 [2] 57 8d }

  condition:
    any of them
}