rule TTP_XOR_WriteProcessMemory_1c86 {
  strings:
    $key_1c86 = { 4b f4 [2] 79 d6 [2] 7f e3 [2] 51 e3 [2] 6e ff }

  condition:
    any of them
}