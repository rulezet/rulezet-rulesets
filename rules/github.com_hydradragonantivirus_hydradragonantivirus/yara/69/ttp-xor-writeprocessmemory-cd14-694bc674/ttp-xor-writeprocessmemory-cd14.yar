rule TTP_XOR_WriteProcessMemory_cd14 {
  strings:
    $key_cd14 = { 9a 66 [2] a8 44 [2] ae 71 [2] 80 71 [2] bf 6d }

  condition:
    any of them
}