rule TTP_XOR_WriteProcessMemory_cd36 {
  strings:
    $key_cd36 = { 9a 44 [2] a8 66 [2] ae 53 [2] 80 53 [2] bf 4f }

  condition:
    any of them
}