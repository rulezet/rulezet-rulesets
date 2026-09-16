rule TTP_XOR_WriteProcessMemory_cd21 {
  strings:
    $key_cd21 = { 9a 53 [2] a8 71 [2] ae 44 [2] 80 44 [2] bf 58 }

  condition:
    any of them
}