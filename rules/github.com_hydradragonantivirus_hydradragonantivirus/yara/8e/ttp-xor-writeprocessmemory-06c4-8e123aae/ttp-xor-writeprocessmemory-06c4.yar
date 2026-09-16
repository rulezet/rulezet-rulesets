rule TTP_XOR_WriteProcessMemory_06c4 {
  strings:
    $key_06c4 = { 51 b6 [2] 63 94 [2] 65 a1 [2] 4b a1 [2] 74 bd }

  condition:
    any of them
}