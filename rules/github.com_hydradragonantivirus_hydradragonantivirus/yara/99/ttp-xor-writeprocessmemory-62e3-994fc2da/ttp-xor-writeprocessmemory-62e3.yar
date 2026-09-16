rule TTP_XOR_WriteProcessMemory_62e3 {
  strings:
    $key_62e3 = { 35 91 [2] 07 b3 [2] 01 86 [2] 2f 86 [2] 10 9a }

  condition:
    any of them
}