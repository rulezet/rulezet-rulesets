rule TTP_XOR_WriteProcessMemory_7ee3 {
  strings:
    $key_7ee3 = { 29 91 [2] 1b b3 [2] 1d 86 [2] 33 86 [2] 0c 9a }

  condition:
    any of them
}