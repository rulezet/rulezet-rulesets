rule TTP_XOR_WriteProcessMemory_d83f {
  strings:
    $key_d83f = { 8f 4d [2] bd 6f [2] bb 5a [2] 95 5a [2] aa 46 }

  condition:
    any of them
}