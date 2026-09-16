rule TTP_XOR_WriteProcessMemory_cf3d {
  strings:
    $key_cf3d = { 98 4f [2] aa 6d [2] ac 58 [2] 82 58 [2] bd 44 }

  condition:
    any of them
}