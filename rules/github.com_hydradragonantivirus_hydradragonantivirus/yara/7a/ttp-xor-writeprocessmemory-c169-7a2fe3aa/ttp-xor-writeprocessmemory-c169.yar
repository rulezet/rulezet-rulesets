rule TTP_XOR_WriteProcessMemory_c169 {
  strings:
    $key_c169 = { 96 1b [2] a4 39 [2] a2 0c [2] 8c 0c [2] b3 10 }

  condition:
    any of them
}