rule TTP_XOR_WriteProcessMemory_cf1a {
  strings:
    $key_cf1a = { 98 68 [2] aa 4a [2] ac 7f [2] 82 7f [2] bd 63 }

  condition:
    any of them
}