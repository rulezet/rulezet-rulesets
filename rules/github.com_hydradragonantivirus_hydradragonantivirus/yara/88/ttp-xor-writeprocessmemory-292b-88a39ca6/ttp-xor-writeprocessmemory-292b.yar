rule TTP_XOR_WriteProcessMemory_292b {
  strings:
    $key_292b = { 7e 59 [2] 4c 7b [2] 4a 4e [2] 64 4e [2] 5b 52 }

  condition:
    any of them
}