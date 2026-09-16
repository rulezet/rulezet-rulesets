rule TTP_XOR_WriteProcessMemory_d80f {
  strings:
    $key_d80f = { 8f 7d [2] bd 5f [2] bb 6a [2] 95 6a [2] aa 76 }

  condition:
    any of them
}