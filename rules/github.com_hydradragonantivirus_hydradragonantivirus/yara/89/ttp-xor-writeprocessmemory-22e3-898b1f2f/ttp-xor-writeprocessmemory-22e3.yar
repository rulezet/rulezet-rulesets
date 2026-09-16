rule TTP_XOR_WriteProcessMemory_22e3 {
  strings:
    $key_22e3 = { 75 91 [2] 47 b3 [2] 41 86 [2] 6f 86 [2] 50 9a }

  condition:
    any of them
}