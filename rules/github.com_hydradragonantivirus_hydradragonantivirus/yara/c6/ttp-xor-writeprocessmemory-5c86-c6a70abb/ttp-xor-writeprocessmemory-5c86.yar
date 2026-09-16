rule TTP_XOR_WriteProcessMemory_5c86 {
  strings:
    $key_5c86 = { 0b f4 [2] 39 d6 [2] 3f e3 [2] 11 e3 [2] 2e ff }

  condition:
    any of them
}