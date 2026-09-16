rule TTP_XOR_WriteProcessMemory_13ed {
  strings:
    $key_13ed = { 44 9f [2] 76 bd [2] 70 88 [2] 5e 88 [2] 61 94 }

  condition:
    any of them
}