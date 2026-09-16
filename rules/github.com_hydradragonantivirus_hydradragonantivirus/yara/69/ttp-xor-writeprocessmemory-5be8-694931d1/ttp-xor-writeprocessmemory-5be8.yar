rule TTP_XOR_WriteProcessMemory_5be8 {
  strings:
    $key_5be8 = { 0c 9a [2] 3e b8 [2] 38 8d [2] 16 8d [2] 29 91 }

  condition:
    any of them
}