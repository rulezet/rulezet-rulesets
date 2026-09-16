rule TTP_XOR_WriteProcessMemory_3fe3 {
  strings:
    $key_3fe3 = { 68 91 [2] 5a b3 [2] 5c 86 [2] 72 86 [2] 4d 9a }

  condition:
    any of them
}