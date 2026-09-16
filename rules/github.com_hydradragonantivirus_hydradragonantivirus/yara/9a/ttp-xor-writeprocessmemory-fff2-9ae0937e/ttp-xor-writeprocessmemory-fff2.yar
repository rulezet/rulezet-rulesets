rule TTP_XOR_WriteProcessMemory_fff2 {
  strings:
    $key_fff2 = { a8 80 [2] 9a a2 [2] 9c 97 [2] b2 97 [2] 8d 8b }

  condition:
    any of them
}