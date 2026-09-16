rule TTP_XOR_WriteProcessMemory_d82a {
  strings:
    $key_d82a = { 8f 58 [2] bd 7a [2] bb 4f [2] 95 4f [2] aa 53 }

  condition:
    any of them
}