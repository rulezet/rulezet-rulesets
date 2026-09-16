rule TTP_XOR_WriteProcessMemory_06b2 {
  strings:
    $key_06b2 = { 51 c0 [2] 63 e2 [2] 65 d7 [2] 4b d7 [2] 74 cb }

  condition:
    any of them
}