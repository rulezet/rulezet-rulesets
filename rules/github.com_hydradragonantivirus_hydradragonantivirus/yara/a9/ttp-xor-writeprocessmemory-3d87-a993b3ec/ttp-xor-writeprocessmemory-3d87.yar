rule TTP_XOR_WriteProcessMemory_3d87 {
  strings:
    $key_3d87 = { 6a f5 [2] 58 d7 [2] 5e e2 [2] 70 e2 [2] 4f fe }

  condition:
    any of them
}