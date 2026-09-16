rule TTP_XOR_WriteProcessMemory_2de1 {
  strings:
    $key_2de1 = { 7a 93 [2] 48 b1 [2] 4e 84 [2] 60 84 [2] 5f 98 }

  condition:
    any of them
}