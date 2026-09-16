rule TTP_XOR_WriteProcessMemory_01b9 {
  strings:
    $key_01b9 = { 56 cb [2] 64 e9 [2] 62 dc [2] 4c dc [2] 73 c0 }

  condition:
    any of them
}