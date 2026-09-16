rule TTP_XOR_WriteProcessMemory_7d01 {
  strings:
    $key_7d01 = { 2a 73 [2] 18 51 [2] 1e 64 [2] 30 64 [2] 0f 78 }

  condition:
    any of them
}