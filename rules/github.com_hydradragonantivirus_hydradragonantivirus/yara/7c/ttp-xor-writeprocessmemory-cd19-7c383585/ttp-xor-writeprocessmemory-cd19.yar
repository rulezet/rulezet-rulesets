rule TTP_XOR_WriteProcessMemory_cd19 {
  strings:
    $key_cd19 = { 9a 6b [2] a8 49 [2] ae 7c [2] 80 7c [2] bf 60 }

  condition:
    any of them
}