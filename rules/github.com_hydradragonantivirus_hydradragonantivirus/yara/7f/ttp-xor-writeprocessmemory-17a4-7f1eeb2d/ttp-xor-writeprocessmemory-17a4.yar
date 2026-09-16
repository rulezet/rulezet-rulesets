rule TTP_XOR_WriteProcessMemory_17a4 {
  strings:
    $key_17a4 = { 40 d6 [2] 72 f4 [2] 74 c1 [2] 5a c1 [2] 65 dd }

  condition:
    any of them
}