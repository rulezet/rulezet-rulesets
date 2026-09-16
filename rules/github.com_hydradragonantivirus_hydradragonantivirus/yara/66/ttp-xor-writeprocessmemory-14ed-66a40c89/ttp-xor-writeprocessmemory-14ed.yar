rule TTP_XOR_WriteProcessMemory_14ed {
  strings:
    $key_14ed = { 43 9f [2] 71 bd [2] 77 88 [2] 59 88 [2] 66 94 }

  condition:
    any of them
}