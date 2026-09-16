rule TTP_XOR_WriteProcessMemory_5301 {
  strings:
    $key_5301 = { 04 73 [2] 36 51 [2] 30 64 [2] 1e 64 [2] 21 78 }

  condition:
    any of them
}