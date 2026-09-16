rule TTP_XOR_WriteProcessMemory_2ddc {
  strings:
    $key_2ddc = { 7a ae [2] 48 8c [2] 4e b9 [2] 60 b9 [2] 5f a5 }

  condition:
    any of them
}