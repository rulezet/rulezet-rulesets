rule TTP_XOR_WriteProcessMemory_0111 {
  strings:
    $key_0111 = { 56 63 [2] 64 41 [2] 62 74 [2] 4c 74 [2] 73 68 }

  condition:
    any of them
}