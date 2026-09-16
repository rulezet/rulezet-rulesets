rule TTP_XOR_WriteProcessMemory_6ec0 {
  strings:
    $key_6ec0 = { 39 b2 [2] 0b 90 [2] 0d a5 [2] 23 a5 [2] 1c b9 }

  condition:
    any of them
}