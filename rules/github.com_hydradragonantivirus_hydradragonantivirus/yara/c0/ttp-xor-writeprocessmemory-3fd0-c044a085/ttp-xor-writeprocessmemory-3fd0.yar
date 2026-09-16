rule TTP_XOR_WriteProcessMemory_3fd0 {
  strings:
    $key_3fd0 = { 68 a2 [2] 5a 80 [2] 5c b5 [2] 72 b5 [2] 4d a9 }

  condition:
    any of them
}