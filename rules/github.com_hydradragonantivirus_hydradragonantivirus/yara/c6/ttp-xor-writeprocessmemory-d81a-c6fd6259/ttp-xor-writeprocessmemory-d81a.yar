rule TTP_XOR_WriteProcessMemory_d81a {
  strings:
    $key_d81a = { 8f 68 [2] bd 4a [2] bb 7f [2] 95 7f [2] aa 63 }

  condition:
    any of them
}