rule TTP_XOR_WriteProcessMemory_61d2 {
  strings:
    $key_61d2 = { 36 a0 [2] 04 82 [2] 02 b7 [2] 2c b7 [2] 13 ab }

  condition:
    any of them
}