rule TTP_XOR_WriteProcessMemory_6de3 {
  strings:
    $key_6de3 = { 3a 91 [2] 08 b3 [2] 0e 86 [2] 20 86 [2] 1f 9a }

  condition:
    any of them
}