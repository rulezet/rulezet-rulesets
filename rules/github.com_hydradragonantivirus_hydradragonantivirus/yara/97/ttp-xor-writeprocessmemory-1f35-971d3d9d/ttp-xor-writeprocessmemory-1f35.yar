rule TTP_XOR_WriteProcessMemory_1f35 {
  strings:
    $key_1f35 = { 48 47 [2] 7a 65 [2] 7c 50 [2] 52 50 [2] 6d 4c }

  condition:
    any of them
}