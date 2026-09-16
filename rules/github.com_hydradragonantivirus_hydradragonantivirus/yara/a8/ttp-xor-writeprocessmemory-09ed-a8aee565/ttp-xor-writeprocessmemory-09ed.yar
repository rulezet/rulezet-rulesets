rule TTP_XOR_WriteProcessMemory_09ed {
  strings:
    $key_09ed = { 5e 9f [2] 6c bd [2] 6a 88 [2] 44 88 [2] 7b 94 }

  condition:
    any of them
}