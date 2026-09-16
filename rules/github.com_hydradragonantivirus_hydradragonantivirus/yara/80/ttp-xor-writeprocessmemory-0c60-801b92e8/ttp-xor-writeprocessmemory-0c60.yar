rule TTP_XOR_WriteProcessMemory_0c60 {
  strings:
    $key_0c60 = { 5b 12 [2] 69 30 [2] 6f 05 [2] 41 05 [2] 7e 19 }

  condition:
    any of them
}