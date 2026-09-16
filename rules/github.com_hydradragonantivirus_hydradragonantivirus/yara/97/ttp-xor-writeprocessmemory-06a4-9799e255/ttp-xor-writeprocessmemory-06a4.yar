rule TTP_XOR_WriteProcessMemory_06a4 {
  strings:
    $key_06a4 = { 51 d6 [2] 63 f4 [2] 65 c1 [2] 4b c1 [2] 74 dd }

  condition:
    any of them
}