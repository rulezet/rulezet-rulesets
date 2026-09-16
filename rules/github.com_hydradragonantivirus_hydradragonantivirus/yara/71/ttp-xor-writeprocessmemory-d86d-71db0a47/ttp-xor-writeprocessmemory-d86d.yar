rule TTP_XOR_WriteProcessMemory_d86d {
  strings:
    $key_d86d = { 8f 1f [2] bd 3d [2] bb 08 [2] 95 08 [2] aa 14 }

  condition:
    any of them
}