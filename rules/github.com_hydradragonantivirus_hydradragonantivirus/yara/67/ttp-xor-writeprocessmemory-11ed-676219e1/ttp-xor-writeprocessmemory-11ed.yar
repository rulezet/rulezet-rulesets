rule TTP_XOR_WriteProcessMemory_11ed {
  strings:
    $key_11ed = { 46 9f [2] 74 bd [2] 72 88 [2] 5c 88 [2] 63 94 }

  condition:
    any of them
}