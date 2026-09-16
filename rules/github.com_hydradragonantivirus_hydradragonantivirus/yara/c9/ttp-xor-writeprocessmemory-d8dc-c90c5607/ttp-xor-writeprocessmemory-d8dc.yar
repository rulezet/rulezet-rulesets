rule TTP_XOR_WriteProcessMemory_d8dc {
  strings:
    $key_d8dc = { 8f ae [2] bd 8c [2] bb b9 [2] 95 b9 [2] aa a5 }

  condition:
    any of them
}