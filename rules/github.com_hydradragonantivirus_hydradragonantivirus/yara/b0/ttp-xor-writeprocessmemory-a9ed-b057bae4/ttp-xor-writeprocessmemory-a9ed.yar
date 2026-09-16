rule TTP_XOR_WriteProcessMemory_a9ed {
  strings:
    $key_a9ed = { fe 9f [2] cc bd [2] ca 88 [2] e4 88 [2] db 94 }

  condition:
    any of them
}