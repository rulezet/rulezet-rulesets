rule TTP_XOR_WriteProcessMemory_cd67 {
  strings:
    $key_cd67 = { 9a 15 [2] a8 37 [2] ae 02 [2] 80 02 [2] bf 1e }

  condition:
    any of them
}