rule TTP_XOR_WriteProcessMemory_cd77 {
  strings:
    $key_cd77 = { 9a 05 [2] a8 27 [2] ae 12 [2] 80 12 [2] bf 0e }

  condition:
    any of them
}