rule TTP_XOR_WriteProcessMemory_26f2 {
  strings:
    $key_26f2 = { 71 80 [2] 43 a2 [2] 45 97 [2] 6b 97 [2] 54 8b }

  condition:
    any of them
}