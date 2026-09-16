rule TTP_XOR_WriteProcessMemory_a923 {
  strings:
    $key_a923 = { fe 51 [2] cc 73 [2] ca 46 [2] e4 46 [2] db 5a }

  condition:
    any of them
}