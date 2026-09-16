rule TTP_XOR_WriteProcessMemory_d81f {
  strings:
    $key_d81f = { 8f 6d [2] bd 4f [2] bb 7a [2] 95 7a [2] aa 66 }

  condition:
    any of them
}