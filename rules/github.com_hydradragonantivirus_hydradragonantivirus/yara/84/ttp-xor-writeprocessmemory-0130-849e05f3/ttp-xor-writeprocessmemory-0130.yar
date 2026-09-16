rule TTP_XOR_WriteProcessMemory_0130 {
  strings:
    $key_0130 = { 56 42 [2] 64 60 [2] 62 55 [2] 4c 55 [2] 73 49 }

  condition:
    any of them
}