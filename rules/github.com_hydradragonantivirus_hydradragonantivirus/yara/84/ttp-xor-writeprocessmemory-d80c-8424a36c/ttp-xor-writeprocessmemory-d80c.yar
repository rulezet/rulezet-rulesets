rule TTP_XOR_WriteProcessMemory_d80c {
  strings:
    $key_d80c = { 8f 7e [2] bd 5c [2] bb 69 [2] 95 69 [2] aa 75 }

  condition:
    any of them
}