rule TTP_XOR_WriteProcessMemory_43ed {
  strings:
    $key_43ed = { 14 9f [2] 26 bd [2] 20 88 [2] 0e 88 [2] 31 94 }

  condition:
    any of them
}