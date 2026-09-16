rule TTP_XOR_WriteProcessMemory_cd07 {
  strings:
    $key_cd07 = { 9a 75 [2] a8 57 [2] ae 62 [2] 80 62 [2] bf 7e }

  condition:
    any of them
}