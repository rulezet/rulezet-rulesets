rule TTP_XOR_WriteProcessMemory_0110 {
  strings:
    $key_0110 = { 56 62 [2] 64 40 [2] 62 75 [2] 4c 75 [2] 73 69 }

  condition:
    any of them
}