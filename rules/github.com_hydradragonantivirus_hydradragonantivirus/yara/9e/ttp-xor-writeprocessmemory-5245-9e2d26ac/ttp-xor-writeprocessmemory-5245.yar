rule TTP_XOR_WriteProcessMemory_5245 {
  strings:
    $key_5245 = { 05 37 [2] 37 15 [2] 31 20 [2] 1f 20 [2] 20 3c }

  condition:
    any of them
}