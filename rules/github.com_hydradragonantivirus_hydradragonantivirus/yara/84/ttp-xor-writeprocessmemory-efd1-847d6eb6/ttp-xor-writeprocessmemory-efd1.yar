rule TTP_XOR_WriteProcessMemory_efd1 {
  strings:
    $key_efd1 = { b8 a3 [2] 8a 81 [2] 8c b4 [2] a2 b4 [2] 9d a8 }

  condition:
    any of them
}