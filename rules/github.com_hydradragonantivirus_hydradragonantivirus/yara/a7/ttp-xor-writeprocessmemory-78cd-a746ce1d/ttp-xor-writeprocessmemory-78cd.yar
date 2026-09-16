rule TTP_XOR_WriteProcessMemory_78cd {
  strings:
    $key_78cd = { 2f bf [2] 1d 9d [2] 1b a8 [2] 35 a8 [2] 0a b4 }

  condition:
    any of them
}