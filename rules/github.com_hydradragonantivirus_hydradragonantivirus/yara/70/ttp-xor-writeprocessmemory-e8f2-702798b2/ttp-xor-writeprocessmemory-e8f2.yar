rule TTP_XOR_WriteProcessMemory_e8f2 {
  strings:
    $key_e8f2 = { bf 80 [2] 8d a2 [2] 8b 97 [2] a5 97 [2] 9a 8b }

  condition:
    any of them
}