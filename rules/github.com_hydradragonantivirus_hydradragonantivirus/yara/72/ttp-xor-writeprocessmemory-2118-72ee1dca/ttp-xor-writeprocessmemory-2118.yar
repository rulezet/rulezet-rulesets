rule TTP_XOR_WriteProcessMemory_2118 {
  strings:
    $key_2118 = { 76 6a [2] 44 48 [2] 42 7d [2] 6c 7d [2] 53 61 }

  condition:
    any of them
}