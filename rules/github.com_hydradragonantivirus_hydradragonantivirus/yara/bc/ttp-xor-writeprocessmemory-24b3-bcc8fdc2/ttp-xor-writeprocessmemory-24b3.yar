rule TTP_XOR_WriteProcessMemory_24b3 {
  strings:
    $key_24b3 = { 73 c1 [2] 41 e3 [2] 47 d6 [2] 69 d6 [2] 56 ca }

  condition:
    any of them
}