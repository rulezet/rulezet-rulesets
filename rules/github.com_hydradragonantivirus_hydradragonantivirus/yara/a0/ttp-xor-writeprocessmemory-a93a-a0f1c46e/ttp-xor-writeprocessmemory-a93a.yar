rule TTP_XOR_WriteProcessMemory_a93a {
  strings:
    $key_a93a = { fe 48 [2] cc 6a [2] ca 5f [2] e4 5f [2] db 43 }

  condition:
    any of them
}