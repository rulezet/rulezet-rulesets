rule TTP_XOR_WriteProcessMemory_0d30 {
  strings:
    $key_0d30 = { 5a 42 [2] 68 60 [2] 6e 55 [2] 40 55 [2] 7f 49 }

  condition:
    any of them
}