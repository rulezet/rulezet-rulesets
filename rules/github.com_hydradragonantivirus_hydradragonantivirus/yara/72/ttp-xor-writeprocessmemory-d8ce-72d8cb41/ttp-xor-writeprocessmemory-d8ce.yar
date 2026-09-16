rule TTP_XOR_WriteProcessMemory_d8ce {
  strings:
    $key_d8ce = { 8f bc [2] bd 9e [2] bb ab [2] 95 ab [2] aa b7 }

  condition:
    any of them
}