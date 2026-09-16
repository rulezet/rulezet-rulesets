rule TTP_XOR_WriteProcessMemory_d87d {
  strings:
    $key_d87d = { 8f 0f [2] bd 2d [2] bb 18 [2] 95 18 [2] aa 04 }

  condition:
    any of them
}