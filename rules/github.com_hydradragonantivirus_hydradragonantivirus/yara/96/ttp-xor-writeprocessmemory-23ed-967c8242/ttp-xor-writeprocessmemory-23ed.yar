rule TTP_XOR_WriteProcessMemory_23ed {
  strings:
    $key_23ed = { 74 9f [2] 46 bd [2] 40 88 [2] 6e 88 [2] 51 94 }

  condition:
    any of them
}