rule TTP_XOR_WriteProcessMemory_cffa {
  strings:
    $key_cffa = { 98 88 [2] aa aa [2] ac 9f [2] 82 9f [2] bd 83 }

  condition:
    any of them
}