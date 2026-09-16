rule TTP_XOR_WriteProcessMemory_e833 {
  strings:
    $key_e833 = { bf 41 [2] 8d 63 [2] 8b 56 [2] a5 56 [2] 9a 4a }

  condition:
    any of them
}