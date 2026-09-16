rule TTP_XOR_WriteProcessMemory_cd34 {
  strings:
    $key_cd34 = { 9a 46 [2] a8 64 [2] ae 51 [2] 80 51 [2] bf 4d }

  condition:
    any of them
}