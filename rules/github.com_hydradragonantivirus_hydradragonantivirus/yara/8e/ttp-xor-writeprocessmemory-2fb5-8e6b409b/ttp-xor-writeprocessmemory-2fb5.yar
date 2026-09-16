rule TTP_XOR_WriteProcessMemory_2fb5 {
  strings:
    $key_2fb5 = { 78 c7 [2] 4a e5 [2] 4c d0 [2] 62 d0 [2] 5d cc }

  condition:
    any of them
}