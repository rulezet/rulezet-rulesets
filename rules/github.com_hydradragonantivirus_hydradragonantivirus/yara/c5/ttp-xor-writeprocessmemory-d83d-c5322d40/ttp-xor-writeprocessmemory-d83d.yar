rule TTP_XOR_WriteProcessMemory_d83d {
  strings:
    $key_d83d = { 8f 4f [2] bd 6d [2] bb 58 [2] 95 58 [2] aa 44 }

  condition:
    any of them
}