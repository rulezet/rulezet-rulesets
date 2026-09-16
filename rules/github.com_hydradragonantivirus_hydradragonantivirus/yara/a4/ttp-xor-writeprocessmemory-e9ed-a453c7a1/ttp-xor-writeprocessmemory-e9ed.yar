rule TTP_XOR_WriteProcessMemory_e9ed {
  strings:
    $key_e9ed = { be 9f [2] 8c bd [2] 8a 88 [2] a4 88 [2] 9b 94 }

  condition:
    any of them
}