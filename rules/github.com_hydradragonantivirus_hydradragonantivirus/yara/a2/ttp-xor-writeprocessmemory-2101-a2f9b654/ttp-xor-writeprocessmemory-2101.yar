rule TTP_XOR_WriteProcessMemory_2101 {
  strings:
    $key_2101 = { 76 73 [2] 44 51 [2] 42 64 [2] 6c 64 [2] 53 78 }

  condition:
    any of them
}