rule TTP_XOR_WriteProcessMemory_05c6 {
  strings:
    $key_05c6 = { 52 b4 [2] 60 96 [2] 66 a3 [2] 48 a3 [2] 77 bf }

  condition:
    any of them
}