rule TTP_XOR_WriteProcessMemory_e870 {
  strings:
    $key_e870 = { bf 02 [2] 8d 20 [2] 8b 15 [2] a5 15 [2] 9a 09 }

  condition:
    any of them
}