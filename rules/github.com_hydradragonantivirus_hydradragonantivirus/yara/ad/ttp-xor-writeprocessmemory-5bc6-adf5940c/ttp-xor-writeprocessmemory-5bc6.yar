rule TTP_XOR_WriteProcessMemory_5bc6 {
  strings:
    $key_5bc6 = { 0c b4 [2] 3e 96 [2] 38 a3 [2] 16 a3 [2] 29 bf }

  condition:
    any of them
}