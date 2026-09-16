rule TTP_XOR_WriteProcessMemory_0107 {
  strings:
    $key_0107 = { 56 75 [2] 64 57 [2] 62 62 [2] 4c 62 [2] 73 7e }

  condition:
    any of them
}