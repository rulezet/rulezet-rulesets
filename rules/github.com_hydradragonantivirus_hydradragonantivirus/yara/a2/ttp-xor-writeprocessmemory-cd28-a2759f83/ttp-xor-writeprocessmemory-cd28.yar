rule TTP_XOR_WriteProcessMemory_cd28 {
  strings:
    $key_cd28 = { 9a 5a [2] a8 78 [2] ae 4d [2] 80 4d [2] bf 51 }

  condition:
    any of them
}