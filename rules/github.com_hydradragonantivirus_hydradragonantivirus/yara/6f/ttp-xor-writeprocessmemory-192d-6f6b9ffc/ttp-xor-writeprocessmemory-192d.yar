rule TTP_XOR_WriteProcessMemory_192d {
  strings:
    $key_192d = { 4e 5f [2] 7c 7d [2] 7a 48 [2] 54 48 [2] 6b 54 }

  condition:
    any of them
}