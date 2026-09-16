rule TTP_XOR_WriteProcessMemory_cd29 {
  strings:
    $key_cd29 = { 9a 5b [2] a8 79 [2] ae 4c [2] 80 4c [2] bf 50 }

  condition:
    any of them
}