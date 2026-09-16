rule TTP_XOR_WriteProcessMemory_24b4 {
  strings:
    $key_24b4 = { 73 c6 [2] 41 e4 [2] 47 d1 [2] 69 d1 [2] 56 cd }

  condition:
    any of them
}