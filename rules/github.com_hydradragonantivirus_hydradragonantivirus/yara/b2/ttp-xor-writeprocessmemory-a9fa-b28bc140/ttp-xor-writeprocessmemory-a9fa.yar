rule TTP_XOR_WriteProcessMemory_a9fa {
  strings:
    $key_a9fa = { fe 88 [2] cc aa [2] ca 9f [2] e4 9f [2] db 83 }

  condition:
    any of them
}