rule TTP_XOR_WriteProcessMemory_393a {
  strings:
    $key_393a = { 6e 48 [2] 5c 6a [2] 5a 5f [2] 74 5f [2] 4b 43 }

  condition:
    any of them
}