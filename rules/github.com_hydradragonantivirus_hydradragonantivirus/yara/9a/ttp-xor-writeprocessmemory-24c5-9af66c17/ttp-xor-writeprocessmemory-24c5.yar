rule TTP_XOR_WriteProcessMemory_24c5 {
  strings:
    $key_24c5 = { 73 b7 [2] 41 95 [2] 47 a0 [2] 69 a0 [2] 56 bc }

  condition:
    any of them
}