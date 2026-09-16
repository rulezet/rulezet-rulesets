rule TTP_XOR_WriteProcessMemory_d8cb {
  strings:
    $key_d8cb = { 8f b9 [2] bd 9b [2] bb ae [2] 95 ae [2] aa b2 }

  condition:
    any of them
}