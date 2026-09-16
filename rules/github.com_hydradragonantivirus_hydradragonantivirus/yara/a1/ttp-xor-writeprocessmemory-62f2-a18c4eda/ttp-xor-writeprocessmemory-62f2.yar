rule TTP_XOR_WriteProcessMemory_62f2 {
  strings:
    $key_62f2 = { 35 80 [2] 07 a2 [2] 01 97 [2] 2f 97 [2] 10 8b }

  condition:
    any of them
}