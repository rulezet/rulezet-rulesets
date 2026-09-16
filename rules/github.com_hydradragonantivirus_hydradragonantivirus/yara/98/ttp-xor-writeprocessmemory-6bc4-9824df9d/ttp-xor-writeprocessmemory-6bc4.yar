rule TTP_XOR_WriteProcessMemory_6bc4 {
  strings:
    $key_6bc4 = { 3c b6 [2] 0e 94 [2] 08 a1 [2] 26 a1 [2] 19 bd }

  condition:
    any of them
}