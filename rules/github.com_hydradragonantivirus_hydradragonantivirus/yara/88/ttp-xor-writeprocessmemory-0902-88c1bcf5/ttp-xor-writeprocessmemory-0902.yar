rule TTP_XOR_WriteProcessMemory_0902 {
  strings:
    $key_0902 = { 5e 70 [2] 6c 52 [2] 6a 67 [2] 44 67 [2] 7b 7b }

  condition:
    any of them
}