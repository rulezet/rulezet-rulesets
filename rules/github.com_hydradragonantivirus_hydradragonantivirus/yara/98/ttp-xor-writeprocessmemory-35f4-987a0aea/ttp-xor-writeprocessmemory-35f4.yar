rule TTP_XOR_WriteProcessMemory_35f4 {
  strings:
    $key_35f4 = { 62 86 [2] 50 a4 [2] 56 91 [2] 78 91 [2] 47 8d }

  condition:
    any of them
}