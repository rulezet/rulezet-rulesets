rule TTP_XOR_WriteProcessMemory_fbc6 {
  strings:
    $key_fbc6 = { ac b4 [2] 9e 96 [2] 98 a3 [2] b6 a3 [2] 89 bf }

  condition:
    any of them
}