rule TTP_XOR_WriteProcessMemory_5cca {
  strings:
    $key_5cca = { 0b b8 [2] 39 9a [2] 3f af [2] 11 af [2] 2e b3 }

  condition:
    any of them
}