rule TTP_XOR_WriteProcessMemory_cfee {
  strings:
    $key_cfee = { 98 9c [2] aa be [2] ac 8b [2] 82 8b [2] bd 97 }

  condition:
    any of them
}