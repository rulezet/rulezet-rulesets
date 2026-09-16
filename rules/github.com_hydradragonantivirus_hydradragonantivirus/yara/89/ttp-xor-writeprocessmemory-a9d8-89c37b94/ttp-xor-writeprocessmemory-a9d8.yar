rule TTP_XOR_WriteProcessMemory_a9d8 {
  strings:
    $key_a9d8 = { fe aa [2] cc 88 [2] ca bd [2] e4 bd [2] db a1 }

  condition:
    any of them
}