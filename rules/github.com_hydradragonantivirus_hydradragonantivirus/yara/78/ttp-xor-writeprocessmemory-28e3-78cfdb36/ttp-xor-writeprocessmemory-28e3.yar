rule TTP_XOR_WriteProcessMemory_28e3 {
  strings:
    $key_28e3 = { 7f 91 [2] 4d b3 [2] 4b 86 [2] 65 86 [2] 5a 9a }

  condition:
    any of them
}