rule TTP_XOR_WriteProcessMemory_0a86 {
  strings:
    $key_0a86 = { 5d f4 [2] 6f d6 [2] 69 e3 [2] 47 e3 [2] 78 ff }

  condition:
    any of them
}