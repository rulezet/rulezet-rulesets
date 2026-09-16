rule TTP_XOR_WriteProcessMemory_43ec {
  strings:
    $key_43ec = { 14 9e [2] 26 bc [2] 20 89 [2] 0e 89 [2] 31 95 }

  condition:
    any of them
}