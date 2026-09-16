rule TTP_XOR_WriteProcessMemory_4dec {
  strings:
    $key_4dec = { 1a 9e [2] 28 bc [2] 2e 89 [2] 00 89 [2] 3f 95 }

  condition:
    any of them
}