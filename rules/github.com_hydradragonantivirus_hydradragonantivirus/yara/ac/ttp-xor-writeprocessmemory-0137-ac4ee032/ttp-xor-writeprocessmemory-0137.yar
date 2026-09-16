rule TTP_XOR_WriteProcessMemory_0137 {
  strings:
    $key_0137 = { 56 45 [2] 64 67 [2] 62 52 [2] 4c 52 [2] 73 4e }

  condition:
    any of them
}