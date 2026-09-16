rule TTP_XOR_WriteProcessMemory_a917 {
  strings:
    $key_a917 = { fe 65 [2] cc 47 [2] ca 72 [2] e4 72 [2] db 6e }

  condition:
    any of them
}