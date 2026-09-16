rule TTP_XOR_WriteProcessMemory_43c6 {
  strings:
    $key_43c6 = { 14 b4 [2] 26 96 [2] 20 a3 [2] 0e a3 [2] 31 bf }

  condition:
    any of them
}