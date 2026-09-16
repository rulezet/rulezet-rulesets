rule TTP_XOR_WriteProcessMemory_3fc4 {
  strings:
    $key_3fc4 = { 68 b6 [2] 5a 94 [2] 5c a1 [2] 72 a1 [2] 4d bd }

  condition:
    any of them
}