rule TTP_XOR_WriteProcessMemory_d805 {
  strings:
    $key_d805 = { 8f 77 [2] bd 55 [2] bb 60 [2] 95 60 [2] aa 7c }

  condition:
    any of them
}