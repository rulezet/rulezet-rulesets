rule TTP_XOR_WriteProcessMemory_cf0a {
  strings:
    $key_cf0a = { 98 78 [2] aa 5a [2] ac 6f [2] 82 6f [2] bd 73 }

  condition:
    any of them
}