rule TTP_XOR_WriteProcessMemory_7d38 {
  strings:
    $key_7d38 = { 2a 4a [2] 18 68 [2] 1e 5d [2] 30 5d [2] 0f 41 }

  condition:
    any of them
}