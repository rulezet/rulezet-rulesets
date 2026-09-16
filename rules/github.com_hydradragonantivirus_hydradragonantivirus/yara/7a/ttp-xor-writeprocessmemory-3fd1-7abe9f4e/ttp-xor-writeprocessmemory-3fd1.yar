rule TTP_XOR_WriteProcessMemory_3fd1 {
  strings:
    $key_3fd1 = { 68 a3 [2] 5a 81 [2] 5c b4 [2] 72 b4 [2] 4d a8 }

  condition:
    any of them
}