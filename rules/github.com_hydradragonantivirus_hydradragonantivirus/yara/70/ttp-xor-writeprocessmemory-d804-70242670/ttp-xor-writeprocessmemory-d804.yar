rule TTP_XOR_WriteProcessMemory_d804 {
  strings:
    $key_d804 = { 8f 76 [2] bd 54 [2] bb 61 [2] 95 61 [2] aa 7d }

  condition:
    any of them
}