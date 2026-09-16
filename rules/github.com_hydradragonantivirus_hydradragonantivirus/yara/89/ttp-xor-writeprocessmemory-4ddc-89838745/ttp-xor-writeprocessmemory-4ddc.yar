rule TTP_XOR_WriteProcessMemory_4ddc {
  strings:
    $key_4ddc = { 1a ae [2] 28 8c [2] 2e b9 [2] 00 b9 [2] 3f a5 }

  condition:
    any of them
}