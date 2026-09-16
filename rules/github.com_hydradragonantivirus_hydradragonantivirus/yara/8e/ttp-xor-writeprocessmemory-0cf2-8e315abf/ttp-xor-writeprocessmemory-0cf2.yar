rule TTP_XOR_WriteProcessMemory_0cf2 {
  strings:
    $key_0cf2 = { 5b 80 [2] 69 a2 [2] 6f 97 [2] 41 97 [2] 7e 8b }

  condition:
    any of them
}