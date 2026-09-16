rule TTP_XOR_WriteProcessMemory_cd6c {
  strings:
    $key_cd6c = { 9a 1e [2] a8 3c [2] ae 09 [2] 80 09 [2] bf 15 }

  condition:
    any of them
}