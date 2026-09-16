rule TTP_XOR_WriteProcessMemory_20f4 {
  strings:
    $key_20f4 = { 77 86 [2] 45 a4 [2] 43 91 [2] 6d 91 [2] 52 8d }

  condition:
    any of them
}