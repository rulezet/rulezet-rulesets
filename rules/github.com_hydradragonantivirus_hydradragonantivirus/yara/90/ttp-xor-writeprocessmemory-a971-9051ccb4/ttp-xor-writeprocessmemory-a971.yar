rule TTP_XOR_WriteProcessMemory_a971 {
  strings:
    $key_a971 = { fe 03 [2] cc 21 [2] ca 14 [2] e4 14 [2] db 08 }

  condition:
    any of them
}