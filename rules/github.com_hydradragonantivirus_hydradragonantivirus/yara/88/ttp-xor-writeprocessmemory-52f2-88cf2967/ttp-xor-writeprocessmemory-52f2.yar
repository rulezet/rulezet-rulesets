rule TTP_XOR_WriteProcessMemory_52f2 {
  strings:
    $key_52f2 = { 05 80 [2] 37 a2 [2] 31 97 [2] 1f 97 [2] 20 8b }

  condition:
    any of them
}