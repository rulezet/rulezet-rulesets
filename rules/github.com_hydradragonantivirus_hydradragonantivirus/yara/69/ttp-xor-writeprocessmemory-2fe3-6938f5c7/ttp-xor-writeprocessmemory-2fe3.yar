rule TTP_XOR_WriteProcessMemory_2fe3 {
  strings:
    $key_2fe3 = { 78 91 [2] 4a b3 [2] 4c 86 [2] 62 86 [2] 5d 9a }

  condition:
    any of them
}