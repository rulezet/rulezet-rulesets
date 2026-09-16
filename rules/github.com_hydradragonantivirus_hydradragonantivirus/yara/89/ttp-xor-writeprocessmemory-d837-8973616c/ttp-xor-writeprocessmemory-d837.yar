rule TTP_XOR_WriteProcessMemory_d837 {
  strings:
    $key_d837 = { 8f 45 [2] bd 67 [2] bb 52 [2] 95 52 [2] aa 4e }

  condition:
    any of them
}