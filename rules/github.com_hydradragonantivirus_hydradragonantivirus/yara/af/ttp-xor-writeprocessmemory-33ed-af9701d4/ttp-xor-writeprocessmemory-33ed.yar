rule TTP_XOR_WriteProcessMemory_33ed {
  strings:
    $key_33ed = { 64 9f [2] 56 bd [2] 50 88 [2] 7e 88 [2] 41 94 }

  condition:
    any of them
}