rule TTP_XOR_WriteProcessMemory_59ed {
  strings:
    $key_59ed = { 0e 9f [2] 3c bd [2] 3a 88 [2] 14 88 [2] 2b 94 }

  condition:
    any of them
}