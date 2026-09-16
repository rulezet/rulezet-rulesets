rule TTP_XOR_WriteProcessMemory_cf6f {
  strings:
    $key_cf6f = { 98 1d [2] aa 3f [2] ac 0a [2] 82 0a [2] bd 16 }

  condition:
    any of them
}