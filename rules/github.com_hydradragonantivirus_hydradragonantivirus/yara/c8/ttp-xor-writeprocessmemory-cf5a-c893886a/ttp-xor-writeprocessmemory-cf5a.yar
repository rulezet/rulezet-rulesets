rule TTP_XOR_WriteProcessMemory_cf5a {
  strings:
    $key_cf5a = { 98 28 [2] aa 0a [2] ac 3f [2] 82 3f [2] bd 23 }

  condition:
    any of them
}