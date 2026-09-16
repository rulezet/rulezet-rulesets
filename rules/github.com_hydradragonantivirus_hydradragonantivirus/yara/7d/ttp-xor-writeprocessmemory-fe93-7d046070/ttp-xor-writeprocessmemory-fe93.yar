rule TTP_XOR_WriteProcessMemory_fe93 {
  strings:
    $key_fe93 = { a9 e1 [2] 9b c3 [2] 9d f6 [2] b3 f6 [2] 8c ea }

  condition:
    any of them
}