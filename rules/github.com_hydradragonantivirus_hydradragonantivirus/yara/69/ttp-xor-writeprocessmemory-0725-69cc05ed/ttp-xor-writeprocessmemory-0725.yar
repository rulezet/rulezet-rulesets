rule TTP_XOR_WriteProcessMemory_0725 {
  strings:
    $key_0725 = { 50 57 [2] 62 75 [2] 64 40 [2] 4a 40 [2] 75 5c }

  condition:
    any of them
}