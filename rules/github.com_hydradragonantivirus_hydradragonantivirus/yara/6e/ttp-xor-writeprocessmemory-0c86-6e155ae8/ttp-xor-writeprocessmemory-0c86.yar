rule TTP_XOR_WriteProcessMemory_0c86 {
  strings:
    $key_0c86 = { 5b f4 [2] 69 d6 [2] 6f e3 [2] 41 e3 [2] 7e ff }

  condition:
    any of them
}