rule TTP_XOR_WriteProcessMemory_38a7 {
  strings:
    $key_38a7 = { 6f d5 [2] 5d f7 [2] 5b c2 [2] 75 c2 [2] 4a de }

  condition:
    any of them
}