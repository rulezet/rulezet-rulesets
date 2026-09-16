rule TTP_XOR_WriteProcessMemory_cd10 {
  strings:
    $key_cd10 = { 9a 62 [2] a8 40 [2] ae 75 [2] 80 75 [2] bf 69 }

  condition:
    any of them
}