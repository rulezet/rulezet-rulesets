rule TTP_XOR_WriteProcessMemory_6690 {
  strings:
    $key_6690 = { 31 e2 [2] 03 c0 [2] 05 f5 [2] 2b f5 [2] 14 e9 }

  condition:
    any of them
}