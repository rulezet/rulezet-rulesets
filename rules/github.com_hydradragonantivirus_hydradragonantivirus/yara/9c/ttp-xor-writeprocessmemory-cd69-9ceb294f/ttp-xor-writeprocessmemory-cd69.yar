rule TTP_XOR_WriteProcessMemory_cd69 {
  strings:
    $key_cd69 = { 9a 1b [2] a8 39 [2] ae 0c [2] 80 0c [2] bf 10 }

  condition:
    any of them
}