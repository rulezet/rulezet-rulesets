rule TTP_XOR_WriteProcessMemory_cd43 {
  strings:
    $key_cd43 = { 9a 31 [2] a8 13 [2] ae 26 [2] 80 26 [2] bf 3a }

  condition:
    any of them
}