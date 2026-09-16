rule TTP_XOR_WriteProcessMemory_0c25 {
  strings:
    $key_0c25 = { 5b 57 [2] 69 75 [2] 6f 40 [2] 41 40 [2] 7e 5c }

  condition:
    any of them
}