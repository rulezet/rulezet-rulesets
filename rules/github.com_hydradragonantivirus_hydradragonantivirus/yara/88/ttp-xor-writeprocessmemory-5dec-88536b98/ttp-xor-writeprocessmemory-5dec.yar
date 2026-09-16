rule TTP_XOR_WriteProcessMemory_5dec {
  strings:
    $key_5dec = { 0a 9e [2] 38 bc [2] 3e 89 [2] 10 89 [2] 2f 95 }

  condition:
    any of them
}