rule TTP_XOR_WriteProcessMemory_c929 {
  strings:
    $key_c929 = { 9e 5b [2] ac 79 [2] aa 4c [2] 84 4c [2] bb 50 }

  condition:
    any of them
}