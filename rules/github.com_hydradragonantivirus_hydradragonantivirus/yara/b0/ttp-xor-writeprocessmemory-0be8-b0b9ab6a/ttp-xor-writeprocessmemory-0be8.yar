rule TTP_XOR_WriteProcessMemory_0be8 {
  strings:
    $key_0be8 = { 5c 9a [2] 6e b8 [2] 68 8d [2] 46 8d [2] 79 91 }

  condition:
    any of them
}