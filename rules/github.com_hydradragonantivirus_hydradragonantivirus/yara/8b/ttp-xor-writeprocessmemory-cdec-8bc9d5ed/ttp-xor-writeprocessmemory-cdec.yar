rule TTP_XOR_WriteProcessMemory_cdec {
  strings:
    $key_cdec = { 9a 9e [2] a8 bc [2] ae 89 [2] 80 89 [2] bf 95 }

  condition:
    any of them
}