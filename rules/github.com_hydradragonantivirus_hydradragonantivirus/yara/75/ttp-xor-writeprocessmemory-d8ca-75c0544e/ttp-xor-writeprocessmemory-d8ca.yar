rule TTP_XOR_WriteProcessMemory_d8ca {
  strings:
    $key_d8ca = { 8f b8 [2] bd 9a [2] bb af [2] 95 af [2] aa b3 }

  condition:
    any of them
}