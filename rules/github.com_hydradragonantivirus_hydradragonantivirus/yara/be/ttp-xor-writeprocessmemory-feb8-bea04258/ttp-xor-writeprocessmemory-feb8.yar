rule TTP_XOR_WriteProcessMemory_feb8 {
  strings:
    $key_feb8 = { a9 ca [2] 9b e8 [2] 9d dd [2] b3 dd [2] 8c c1 }

  condition:
    any of them
}