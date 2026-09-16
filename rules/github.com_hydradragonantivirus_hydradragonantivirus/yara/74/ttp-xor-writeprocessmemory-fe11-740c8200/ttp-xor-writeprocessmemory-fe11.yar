rule TTP_XOR_WriteProcessMemory_fe11 {
  strings:
    $key_fe11 = { a9 63 [2] 9b 41 [2] 9d 74 [2] b3 74 [2] 8c 68 }

  condition:
    any of them
}