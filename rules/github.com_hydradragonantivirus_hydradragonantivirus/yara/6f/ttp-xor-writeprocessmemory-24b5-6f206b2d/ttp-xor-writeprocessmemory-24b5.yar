rule TTP_XOR_WriteProcessMemory_24b5 {
  strings:
    $key_24b5 = { 73 c7 [2] 41 e5 [2] 47 d0 [2] 69 d0 [2] 56 cc }

  condition:
    any of them
}