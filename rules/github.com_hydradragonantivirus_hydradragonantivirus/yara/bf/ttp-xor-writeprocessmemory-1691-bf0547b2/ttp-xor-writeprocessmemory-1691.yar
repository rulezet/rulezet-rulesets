rule TTP_XOR_WriteProcessMemory_1691 {
  strings:
    $key_1691 = { 41 e3 [2] 73 c1 [2] 75 f4 [2] 5b f4 [2] 64 e8 }

  condition:
    any of them
}