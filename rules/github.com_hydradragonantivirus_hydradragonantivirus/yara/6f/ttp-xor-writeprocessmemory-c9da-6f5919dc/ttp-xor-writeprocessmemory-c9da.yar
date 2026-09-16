rule TTP_XOR_WriteProcessMemory_c9da {
  strings:
    $key_c9da = { 9e a8 [2] ac 8a [2] aa bf [2] 84 bf [2] bb a3 }

  condition:
    any of them
}