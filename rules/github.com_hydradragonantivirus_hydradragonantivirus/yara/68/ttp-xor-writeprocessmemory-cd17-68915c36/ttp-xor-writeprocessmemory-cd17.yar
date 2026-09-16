rule TTP_XOR_WriteProcessMemory_cd17 {
  strings:
    $key_cd17 = { 9a 65 [2] a8 47 [2] ae 72 [2] 80 72 [2] bf 6e }

  condition:
    any of them
}