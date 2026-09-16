rule TTP_XOR_WriteProcessMemory_0be3 {
  strings:
    $key_0be3 = { 5c 91 [2] 6e b3 [2] 68 86 [2] 46 86 [2] 79 9a }

  condition:
    any of them
}