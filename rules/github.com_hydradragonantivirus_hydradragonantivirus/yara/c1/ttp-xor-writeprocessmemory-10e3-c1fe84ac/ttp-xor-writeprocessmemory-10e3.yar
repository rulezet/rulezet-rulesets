rule TTP_XOR_WriteProcessMemory_10e3 {
  strings:
    $key_10e3 = { 47 91 [2] 75 b3 [2] 73 86 [2] 5d 86 [2] 62 9a }

  condition:
    any of them
}