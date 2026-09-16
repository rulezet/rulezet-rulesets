rule TTP_XOR_WriteProcessMemory_cf4f {
  strings:
    $key_cf4f = { 98 3d [2] aa 1f [2] ac 2a [2] 82 2a [2] bd 36 }

  condition:
    any of them
}