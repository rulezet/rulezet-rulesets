rule TTP_XOR_WriteProcessMemory_e4ed {
  strings:
    $key_e4ed = { b3 9f [2] 81 bd [2] 87 88 [2] a9 88 [2] 96 94 }

  condition:
    any of them
}