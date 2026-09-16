rule TTP_XOR_WriteProcessMemory_a9ef {
  strings:
    $key_a9ef = { fe 9d [2] cc bf [2] ca 8a [2] e4 8a [2] db 96 }

  condition:
    any of them
}