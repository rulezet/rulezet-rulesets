rule TTP_XOR_WriteProcessMemory_7d28 {
  strings:
    $key_7d28 = { 2a 5a [2] 18 78 [2] 1e 4d [2] 30 4d [2] 0f 51 }

  condition:
    any of them
}