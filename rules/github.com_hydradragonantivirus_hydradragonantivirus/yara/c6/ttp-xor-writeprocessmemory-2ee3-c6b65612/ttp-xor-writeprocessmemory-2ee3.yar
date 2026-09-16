rule TTP_XOR_WriteProcessMemory_2ee3 {
  strings:
    $key_2ee3 = { 79 91 [2] 4b b3 [2] 4d 86 [2] 63 86 [2] 5c 9a }

  condition:
    any of them
}