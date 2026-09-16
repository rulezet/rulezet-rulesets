rule TTP_XOR_WriteProcessMemory_fe01 {
  strings:
    $key_fe01 = { a9 73 [2] 9b 51 [2] 9d 64 [2] b3 64 [2] 8c 78 }

  condition:
    any of them
}