rule TTP_XOR_WriteProcessMemory_7b24 {
  strings:
    $key_7b24 = { 2c 56 [2] 1e 74 [2] 18 41 [2] 36 41 [2] 09 5d }

  condition:
    any of them
}