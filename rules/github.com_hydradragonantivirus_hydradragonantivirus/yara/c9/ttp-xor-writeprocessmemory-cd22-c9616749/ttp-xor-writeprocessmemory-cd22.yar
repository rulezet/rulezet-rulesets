rule TTP_XOR_WriteProcessMemory_cd22 {
  strings:
    $key_cd22 = { 9a 50 [2] a8 72 [2] ae 47 [2] 80 47 [2] bf 5b }

  condition:
    any of them
}