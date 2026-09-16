rule TTP_XOR_WriteProcessMemory_03ed {
  strings:
    $key_03ed = { 54 9f [2] 66 bd [2] 60 88 [2] 4e 88 [2] 71 94 }

  condition:
    any of them
}