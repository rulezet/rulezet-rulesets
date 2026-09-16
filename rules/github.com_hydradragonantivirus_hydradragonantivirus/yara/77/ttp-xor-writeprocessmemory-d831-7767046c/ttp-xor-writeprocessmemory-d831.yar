rule TTP_XOR_WriteProcessMemory_d831 {
  strings:
    $key_d831 = { 8f 43 [2] bd 61 [2] bb 54 [2] 95 54 [2] aa 48 }

  condition:
    any of them
}