rule TTP_XOR_WriteProcessMemory_d81d {
  strings:
    $key_d81d = { 8f 6f [2] bd 4d [2] bb 78 [2] 95 78 [2] aa 64 }

  condition:
    any of them
}