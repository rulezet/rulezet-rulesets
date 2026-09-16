rule TTP_XOR_WriteProcessMemory_56e3 {
  strings:
    $key_56e3 = { 01 91 [2] 33 b3 [2] 35 86 [2] 1b 86 [2] 24 9a }

  condition:
    any of them
}