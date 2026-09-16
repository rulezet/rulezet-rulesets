rule TTP_XOR_WriteProcessMemory_efb9 {
  strings:
    $key_efb9 = { b8 cb [2] 8a e9 [2] 8c dc [2] a2 dc [2] 9d c0 }

  condition:
    any of them
}