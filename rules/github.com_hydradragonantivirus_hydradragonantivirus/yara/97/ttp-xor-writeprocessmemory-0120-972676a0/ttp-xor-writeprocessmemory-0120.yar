rule TTP_XOR_WriteProcessMemory_0120 {
  strings:
    $key_0120 = { 56 52 [2] 64 70 [2] 62 45 [2] 4c 45 [2] 73 59 }

  condition:
    any of them
}