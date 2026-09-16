rule TTP_XOR_WriteProcessMemory_3ac6 {
  strings:
    $key_3ac6 = { 6d b4 [2] 5f 96 [2] 59 a3 [2] 77 a3 [2] 48 bf }

  condition:
    any of them
}