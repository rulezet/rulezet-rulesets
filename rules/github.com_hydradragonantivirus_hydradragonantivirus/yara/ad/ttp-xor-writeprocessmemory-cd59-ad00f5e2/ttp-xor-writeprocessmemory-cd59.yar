rule TTP_XOR_WriteProcessMemory_cd59 {
  strings:
    $key_cd59 = { 9a 2b [2] a8 09 [2] ae 3c [2] 80 3c [2] bf 20 }

  condition:
    any of them
}