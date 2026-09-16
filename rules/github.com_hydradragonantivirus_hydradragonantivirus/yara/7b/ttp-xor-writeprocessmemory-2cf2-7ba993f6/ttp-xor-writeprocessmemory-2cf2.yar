rule TTP_XOR_WriteProcessMemory_2cf2 {
  strings:
    $key_2cf2 = { 7b 80 [2] 49 a2 [2] 4f 97 [2] 61 97 [2] 5e 8b }

  condition:
    any of them
}