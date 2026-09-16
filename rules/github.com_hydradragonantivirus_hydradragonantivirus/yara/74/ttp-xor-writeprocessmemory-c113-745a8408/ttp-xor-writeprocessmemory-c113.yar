rule TTP_XOR_WriteProcessMemory_c113 {
  strings:
    $key_c113 = { 96 61 [2] a4 43 [2] a2 76 [2] 8c 76 [2] b3 6a }

  condition:
    any of them
}