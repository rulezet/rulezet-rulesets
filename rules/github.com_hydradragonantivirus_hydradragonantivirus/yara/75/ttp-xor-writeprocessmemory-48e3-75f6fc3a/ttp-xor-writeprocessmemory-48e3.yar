rule TTP_XOR_WriteProcessMemory_48e3 {
  strings:
    $key_48e3 = { 1f 91 [2] 2d b3 [2] 2b 86 [2] 05 86 [2] 3a 9a }

  condition:
    any of them
}