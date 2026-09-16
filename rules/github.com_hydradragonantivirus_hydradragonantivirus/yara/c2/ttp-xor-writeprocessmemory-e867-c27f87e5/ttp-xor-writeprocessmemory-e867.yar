rule TTP_XOR_WriteProcessMemory_e867 {
  strings:
    $key_e867 = { bf 15 [2] 8d 37 [2] 8b 02 [2] a5 02 [2] 9a 1e }

  condition:
    any of them
}