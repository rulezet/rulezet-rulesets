rule TTP_XOR_WriteProcessMemory_39ed {
  strings:
    $key_39ed = { 6e 9f [2] 5c bd [2] 5a 88 [2] 74 88 [2] 4b 94 }

  condition:
    any of them
}