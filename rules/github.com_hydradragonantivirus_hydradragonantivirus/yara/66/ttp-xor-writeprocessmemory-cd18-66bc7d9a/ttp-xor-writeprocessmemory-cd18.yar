rule TTP_XOR_WriteProcessMemory_cd18 {
  strings:
    $key_cd18 = { 9a 6a [2] a8 48 [2] ae 7d [2] 80 7d [2] bf 61 }

  condition:
    any of them
}