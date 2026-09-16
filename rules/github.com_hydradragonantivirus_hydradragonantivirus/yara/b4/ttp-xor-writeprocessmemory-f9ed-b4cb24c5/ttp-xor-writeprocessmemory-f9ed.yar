rule TTP_XOR_WriteProcessMemory_f9ed {
  strings:
    $key_f9ed = { ae 9f [2] 9c bd [2] 9a 88 [2] b4 88 [2] 8b 94 }

  condition:
    any of them
}