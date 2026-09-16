rule TTP_XOR_WriteProcessMemory_cff4 {
  strings:
    $key_cff4 = { 98 86 [2] aa a4 [2] ac 91 [2] 82 91 [2] bd 8d }

  condition:
    any of them
}