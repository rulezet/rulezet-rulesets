rule TTP_XOR_WriteProcessMemory_6ddc {
  strings:
    $key_6ddc = { 3a ae [2] 08 8c [2] 0e b9 [2] 20 b9 [2] 1f a5 }

  condition:
    any of them
}