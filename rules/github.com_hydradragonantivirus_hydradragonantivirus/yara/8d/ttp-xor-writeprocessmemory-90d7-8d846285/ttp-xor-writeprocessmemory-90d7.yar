rule TTP_XOR_WriteProcessMemory_90d7 {
  strings:
    $key_90d7 = { c7 a5 [2] f5 87 [2] f3 b2 [2] dd b2 [2] e2 ae }

  condition:
    any of them
}