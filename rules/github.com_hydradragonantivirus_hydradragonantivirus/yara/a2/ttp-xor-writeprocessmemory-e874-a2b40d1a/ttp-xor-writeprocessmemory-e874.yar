rule TTP_XOR_WriteProcessMemory_e874 {
  strings:
    $key_e874 = { bf 06 [2] 8d 24 [2] 8b 11 [2] a5 11 [2] 9a 0d }

  condition:
    any of them
}