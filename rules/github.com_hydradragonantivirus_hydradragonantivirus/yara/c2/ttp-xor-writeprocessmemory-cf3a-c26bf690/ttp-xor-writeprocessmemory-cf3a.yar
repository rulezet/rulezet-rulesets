rule TTP_XOR_WriteProcessMemory_cf3a {
  strings:
    $key_cf3a = { 98 48 [2] aa 6a [2] ac 5f [2] 82 5f [2] bd 43 }

  condition:
    any of them
}