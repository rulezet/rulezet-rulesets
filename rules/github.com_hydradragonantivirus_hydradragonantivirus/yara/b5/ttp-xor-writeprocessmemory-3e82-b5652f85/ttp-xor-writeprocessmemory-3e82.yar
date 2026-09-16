rule TTP_XOR_WriteProcessMemory_3e82 {
  strings:
    $key_3e82 = { 69 f0 [2] 5b d2 [2] 5d e7 [2] 73 e7 [2] 4c fb }

  condition:
    any of them
}