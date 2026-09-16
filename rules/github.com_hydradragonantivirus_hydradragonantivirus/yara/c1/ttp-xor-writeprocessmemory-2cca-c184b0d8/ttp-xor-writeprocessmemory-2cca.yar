rule TTP_XOR_WriteProcessMemory_2cca {
  strings:
    $key_2cca = { 7b b8 [2] 49 9a [2] 4f af [2] 61 af [2] 5e b3 }

  condition:
    any of them
}