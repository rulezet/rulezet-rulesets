rule TTP_XOR_WriteProcessMemory_ecca {
  strings:
    $key_ecca = { bb b8 [2] 89 9a [2] 8f af [2] a1 af [2] 9e b3 }

  condition:
    any of them
}