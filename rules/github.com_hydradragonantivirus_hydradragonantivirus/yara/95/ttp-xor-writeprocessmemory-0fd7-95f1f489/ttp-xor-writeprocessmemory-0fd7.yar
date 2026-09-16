rule TTP_XOR_WriteProcessMemory_0fd7 {
  strings:
    $key_0fd7 = { 58 a5 [2] 6a 87 [2] 6c b2 [2] 42 b2 [2] 7d ae }

  condition:
    any of them
}