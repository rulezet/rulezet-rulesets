rule TTP_XOR_WriteProcessMemory_2fd1 {
  strings:
    $key_2fd1 = { 78 a3 [2] 4a 81 [2] 4c b4 [2] 62 b4 [2] 5d a8 }

  condition:
    any of them
}