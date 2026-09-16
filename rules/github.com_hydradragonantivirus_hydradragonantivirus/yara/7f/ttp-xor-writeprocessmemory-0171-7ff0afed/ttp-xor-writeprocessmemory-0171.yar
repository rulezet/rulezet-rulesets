rule TTP_XOR_WriteProcessMemory_0171 {
  strings:
    $key_0171 = { 56 03 [2] 64 21 [2] 62 14 [2] 4c 14 [2] 73 08 }

  condition:
    any of them
}