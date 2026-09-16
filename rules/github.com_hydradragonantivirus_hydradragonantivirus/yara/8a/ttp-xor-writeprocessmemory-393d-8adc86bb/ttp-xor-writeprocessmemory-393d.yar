rule TTP_XOR_WriteProcessMemory_393d {
  strings:
    $key_393d = { 6e 4f [2] 5c 6d [2] 5a 58 [2] 74 58 [2] 4b 44 }

  condition:
    any of them
}