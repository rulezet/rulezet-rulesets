rule TTP_XOR_WriteProcessMemory_24a2 {
  strings:
    $key_24a2 = { 73 d0 [2] 41 f2 [2] 47 c7 [2] 69 c7 [2] 56 db }

  condition:
    any of them
}