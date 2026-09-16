rule TTP_XOR_WriteProcessMemory_cd97 {
  strings:
    $key_cd97 = { 9a e5 [2] a8 c7 [2] ae f2 [2] 80 f2 [2] bf ee }

  condition:
    any of them
}