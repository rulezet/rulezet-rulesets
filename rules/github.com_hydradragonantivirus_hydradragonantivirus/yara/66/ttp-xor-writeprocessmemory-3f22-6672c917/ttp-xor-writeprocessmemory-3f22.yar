rule TTP_XOR_WriteProcessMemory_3f22 {
  strings:
    $key_3f22 = { 68 50 [2] 5a 72 [2] 5c 47 [2] 72 47 [2] 4d 5b }

  condition:
    any of them
}