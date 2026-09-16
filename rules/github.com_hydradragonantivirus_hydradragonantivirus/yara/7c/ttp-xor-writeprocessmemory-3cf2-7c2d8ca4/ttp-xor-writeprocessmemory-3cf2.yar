rule TTP_XOR_WriteProcessMemory_3cf2 {
  strings:
    $key_3cf2 = { 6b 80 [2] 59 a2 [2] 5f 97 [2] 71 97 [2] 4e 8b }

  condition:
    any of them
}