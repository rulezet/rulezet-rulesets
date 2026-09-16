rule TTP_XOR_WriteProcessMemory_cd64 {
  strings:
    $key_cd64 = { 9a 16 [2] a8 34 [2] ae 01 [2] 80 01 [2] bf 1d }

  condition:
    any of them
}