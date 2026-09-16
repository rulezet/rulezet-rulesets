rule TTP_XOR_WriteProcessMemory_fddd {
  strings:
    $key_fddd = { aa af [2] 98 8d [2] 9e b8 [2] b0 b8 [2] 8f a4 }

  condition:
    any of them
}