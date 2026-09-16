rule TTP_XOR_WriteProcessMemory_cd47 {
  strings:
    $key_cd47 = { 9a 35 [2] a8 17 [2] ae 22 [2] 80 22 [2] bf 3e }

  condition:
    any of them
}