rule TTP_XOR_WriteProcessMemory_d84f {
  strings:
    $key_d84f = { 8f 3d [2] bd 1f [2] bb 2a [2] 95 2a [2] aa 36 }

  condition:
    any of them
}