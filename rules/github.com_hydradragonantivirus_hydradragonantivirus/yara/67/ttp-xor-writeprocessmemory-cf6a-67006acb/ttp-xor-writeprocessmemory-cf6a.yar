rule TTP_XOR_WriteProcessMemory_cf6a {
  strings:
    $key_cf6a = { 98 18 [2] aa 3a [2] ac 0f [2] 82 0f [2] bd 13 }

  condition:
    any of them
}