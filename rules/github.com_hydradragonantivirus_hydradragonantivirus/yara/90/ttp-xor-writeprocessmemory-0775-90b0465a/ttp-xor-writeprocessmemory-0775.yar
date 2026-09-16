rule TTP_XOR_WriteProcessMemory_0775 {
  strings:
    $key_0775 = { 50 07 [2] 62 25 [2] 64 10 [2] 4a 10 [2] 75 0c }

  condition:
    any of them
}