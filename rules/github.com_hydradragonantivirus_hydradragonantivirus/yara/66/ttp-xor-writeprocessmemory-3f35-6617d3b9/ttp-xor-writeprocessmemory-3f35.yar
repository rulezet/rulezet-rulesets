rule TTP_XOR_WriteProcessMemory_3f35 {
  strings:
    $key_3f35 = { 68 47 [2] 5a 65 [2] 5c 50 [2] 72 50 [2] 4d 4c }

  condition:
    any of them
}