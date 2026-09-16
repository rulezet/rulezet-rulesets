rule TTP_XOR_WriteProcessMemory_cd82 {
  strings:
    $key_cd82 = { 9a f0 [2] a8 d2 [2] ae e7 [2] 80 e7 [2] bf fb }

  condition:
    any of them
}