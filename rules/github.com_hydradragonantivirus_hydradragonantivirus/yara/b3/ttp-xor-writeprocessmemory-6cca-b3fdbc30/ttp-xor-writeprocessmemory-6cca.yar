rule TTP_XOR_WriteProcessMemory_6cca {
  strings:
    $key_6cca = { 3b b8 [2] 09 9a [2] 0f af [2] 21 af [2] 1e b3 }

  condition:
    any of them
}