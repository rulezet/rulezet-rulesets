rule TTP_XOR_WriteProcessMemory_14c6 {
  strings:
    $key_14c6 = { 43 b4 [2] 71 96 [2] 77 a3 [2] 59 a3 [2] 66 bf }

  condition:
    any of them
}