rule TTP_XOR_WriteProcessMemory_cd2e {
  strings:
    $key_cd2e = { 9a 5c [2] a8 7e [2] ae 4b [2] 80 4b [2] bf 57 }

  condition:
    any of them
}