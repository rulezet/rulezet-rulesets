rule TTP_XOR_WriteProcessMemory_40f4 {
  strings:
    $key_40f4 = { 17 86 [2] 25 a4 [2] 23 91 [2] 0d 91 [2] 32 8d }

  condition:
    any of them
}