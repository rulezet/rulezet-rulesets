rule TTP_XOR_WriteProcessMemory_7df8 {
  strings:
    $key_7df8 = { 2a 8a [2] 18 a8 [2] 1e 9d [2] 30 9d [2] 0f 81 }

  condition:
    any of them
}