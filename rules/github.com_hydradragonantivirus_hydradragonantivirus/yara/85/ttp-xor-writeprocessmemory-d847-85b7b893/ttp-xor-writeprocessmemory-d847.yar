rule TTP_XOR_WriteProcessMemory_d847 {
  strings:
    $key_d847 = { 8f 35 [2] bd 17 [2] bb 22 [2] 95 22 [2] aa 3e }

  condition:
    any of them
}