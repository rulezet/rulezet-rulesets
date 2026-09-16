rule TTP_XOR_WriteProcessMemory_78e3 {
  strings:
    $key_78e3 = { 2f 91 [2] 1d b3 [2] 1b 86 [2] 35 86 [2] 0a 9a }

  condition:
    any of them
}