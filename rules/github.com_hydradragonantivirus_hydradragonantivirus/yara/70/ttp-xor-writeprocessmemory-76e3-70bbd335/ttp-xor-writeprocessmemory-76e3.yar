rule TTP_XOR_WriteProcessMemory_76e3 {
  strings:
    $key_76e3 = { 21 91 [2] 13 b3 [2] 15 86 [2] 3b 86 [2] 04 9a }

  condition:
    any of them
}