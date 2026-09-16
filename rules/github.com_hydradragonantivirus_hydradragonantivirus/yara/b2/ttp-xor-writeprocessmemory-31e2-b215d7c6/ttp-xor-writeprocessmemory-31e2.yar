rule TTP_XOR_WriteProcessMemory_31e2 {
  strings:
    $key_31e2 = { 66 90 [2] 54 b2 [2] 52 87 [2] 7c 87 [2] 43 9b }

  condition:
    any of them
}