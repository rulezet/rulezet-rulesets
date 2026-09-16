rule TTP_XOR_WriteProcessMemory_a964 {
  strings:
    $key_a964 = { fe 16 [2] cc 34 [2] ca 01 [2] e4 01 [2] db 1d }

  condition:
    any of them
}