rule TTP_XOR_WriteProcessMemory_cd1e {
  strings:
    $key_cd1e = { 9a 6c [2] a8 4e [2] ae 7b [2] 80 7b [2] bf 67 }

  condition:
    any of them
}