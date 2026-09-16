rule TTP_XOR_WriteProcessMemory_e6c6 {
  strings:
    $key_e6c6 = { b1 b4 [2] 83 96 [2] 85 a3 [2] ab a3 [2] 94 bf }

  condition:
    any of them
}