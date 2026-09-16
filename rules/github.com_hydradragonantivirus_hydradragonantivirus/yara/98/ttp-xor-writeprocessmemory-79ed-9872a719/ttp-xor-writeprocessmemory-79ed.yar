rule TTP_XOR_WriteProcessMemory_79ed {
  strings:
    $key_79ed = { 2e 9f [2] 1c bd [2] 1a 88 [2] 34 88 [2] 0b 94 }

  condition:
    any of them
}