rule TTP_XOR_WriteProcessMemory_3fb9 {
  strings:
    $key_3fb9 = { 68 cb [2] 5a e9 [2] 5c dc [2] 72 dc [2] 4d c0 }

  condition:
    any of them
}