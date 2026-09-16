rule TTP_XOR_WriteProcessMemory_0dec {
  strings:
    $key_0dec = { 5a 9e [2] 68 bc [2] 6e 89 [2] 40 89 [2] 7f 95 }

  condition:
    any of them
}