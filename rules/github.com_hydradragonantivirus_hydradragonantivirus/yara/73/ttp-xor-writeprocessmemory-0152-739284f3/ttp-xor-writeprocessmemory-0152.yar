rule TTP_XOR_WriteProcessMemory_0152 {
  strings:
    $key_0152 = { 56 20 [2] 64 02 [2] 62 37 [2] 4c 37 [2] 73 2b }

  condition:
    any of them
}