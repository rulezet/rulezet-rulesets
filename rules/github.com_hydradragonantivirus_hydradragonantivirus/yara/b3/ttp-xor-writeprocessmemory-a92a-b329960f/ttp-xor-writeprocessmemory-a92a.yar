rule TTP_XOR_WriteProcessMemory_a92a {
  strings:
    $key_a92a = { fe 58 [2] cc 7a [2] ca 4f [2] e4 4f [2] db 53 }

  condition:
    any of them
}