rule TTP_XOR_WriteProcessMemory_0c35 {
  strings:
    $key_0c35 = { 5b 47 [2] 69 65 [2] 6f 50 [2] 41 50 [2] 7e 4c }

  condition:
    any of them
}