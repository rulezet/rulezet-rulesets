rule TTP_XOR_WriteProcessMemory_a9fe {
  strings:
    $key_a9fe = { fe 8c [2] cc ae [2] ca 9b [2] e4 9b [2] db 87 }

  condition:
    any of them
}