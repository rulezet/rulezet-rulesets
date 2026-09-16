rule TTP_XOR_WriteProcessMemory_d84a {
  strings:
    $key_d84a = { 8f 38 [2] bd 1a [2] bb 2f [2] 95 2f [2] aa 33 }

  condition:
    any of them
}