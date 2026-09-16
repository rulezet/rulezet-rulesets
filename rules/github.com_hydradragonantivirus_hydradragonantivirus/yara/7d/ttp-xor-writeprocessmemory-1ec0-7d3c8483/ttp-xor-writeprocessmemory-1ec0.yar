rule TTP_XOR_WriteProcessMemory_1ec0 {
  strings:
    $key_1ec0 = { 49 b2 [2] 7b 90 [2] 7d a5 [2] 53 a5 [2] 6c b9 }

  condition:
    any of them
}