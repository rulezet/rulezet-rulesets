rule TTP_XOR_WriteProcessMemory_cfe5 {
  strings:
    $key_cfe5 = { 98 97 [2] aa b5 [2] ac 80 [2] 82 80 [2] bd 9c }

  condition:
    any of them
}