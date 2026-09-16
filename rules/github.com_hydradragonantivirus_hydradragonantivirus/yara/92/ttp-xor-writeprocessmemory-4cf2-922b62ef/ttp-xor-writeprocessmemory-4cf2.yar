rule TTP_XOR_WriteProcessMemory_4cf2 {
  strings:
    $key_4cf2 = { 1b 80 [2] 29 a2 [2] 2f 97 [2] 01 97 [2] 3e 8b }

  condition:
    any of them
}