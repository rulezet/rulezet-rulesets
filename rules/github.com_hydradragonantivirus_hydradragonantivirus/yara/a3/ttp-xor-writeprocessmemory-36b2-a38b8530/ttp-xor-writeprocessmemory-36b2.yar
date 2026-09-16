rule TTP_XOR_WriteProcessMemory_36b2 {
  strings:
    $key_36b2 = { 61 c0 [2] 53 e2 [2] 55 d7 [2] 7b d7 [2] 44 cb }

  condition:
    any of them
}