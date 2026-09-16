rule TTP_XOR_WriteProcessMemory_2f35 {
  strings:
    $key_2f35 = { 78 47 [2] 4a 65 [2] 4c 50 [2] 62 50 [2] 5d 4c }

  condition:
    any of them
}