rule TTP_XOR_WriteProcessMemory_7dcb {
  strings:
    $key_7dcb = { 2a b9 [2] 18 9b [2] 1e ae [2] 30 ae [2] 0f b2 }

  condition:
    any of them
}