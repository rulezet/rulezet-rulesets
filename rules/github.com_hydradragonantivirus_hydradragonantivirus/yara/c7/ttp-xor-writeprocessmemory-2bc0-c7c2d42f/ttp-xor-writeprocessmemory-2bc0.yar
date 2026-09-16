rule TTP_XOR_WriteProcessMemory_2bc0 {
  strings:
    $key_2bc0 = { 7c b2 [2] 4e 90 [2] 48 a5 [2] 66 a5 [2] 59 b9 }

  condition:
    any of them
}