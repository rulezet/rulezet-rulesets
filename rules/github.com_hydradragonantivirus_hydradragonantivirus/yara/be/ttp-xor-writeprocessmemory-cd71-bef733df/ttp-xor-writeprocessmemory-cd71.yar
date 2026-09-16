rule TTP_XOR_WriteProcessMemory_cd71 {
  strings:
    $key_cd71 = { 9a 03 [2] a8 21 [2] ae 14 [2] 80 14 [2] bf 08 }

  condition:
    any of them
}