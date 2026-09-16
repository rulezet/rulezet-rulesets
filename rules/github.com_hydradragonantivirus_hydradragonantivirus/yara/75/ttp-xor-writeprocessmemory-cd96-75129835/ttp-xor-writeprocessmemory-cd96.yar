rule TTP_XOR_WriteProcessMemory_cd96 {
  strings:
    $key_cd96 = { 9a e4 [2] a8 c6 [2] ae f3 [2] 80 f3 [2] bf ef }

  condition:
    any of them
}