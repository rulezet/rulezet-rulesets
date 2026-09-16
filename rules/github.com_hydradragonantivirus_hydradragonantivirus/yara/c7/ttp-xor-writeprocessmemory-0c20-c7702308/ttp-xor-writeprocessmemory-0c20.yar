rule TTP_XOR_WriteProcessMemory_0c20 {
  strings:
    $key_0c20 = { 5b 52 [2] 69 70 [2] 6f 45 [2] 41 45 [2] 7e 59 }

  condition:
    any of them
}