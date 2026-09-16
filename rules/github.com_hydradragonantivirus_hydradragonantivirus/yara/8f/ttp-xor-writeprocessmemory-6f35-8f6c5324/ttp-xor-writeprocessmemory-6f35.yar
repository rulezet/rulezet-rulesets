rule TTP_XOR_WriteProcessMemory_6f35 {
  strings:
    $key_6f35 = { 38 47 [2] 0a 65 [2] 0c 50 [2] 22 50 [2] 1d 4c }

  condition:
    any of them
}