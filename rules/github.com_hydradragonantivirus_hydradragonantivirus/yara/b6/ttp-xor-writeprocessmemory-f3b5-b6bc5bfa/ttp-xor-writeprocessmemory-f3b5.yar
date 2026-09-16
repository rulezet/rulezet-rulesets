rule TTP_XOR_WriteProcessMemory_f3b5 {
  strings:
    $key_f3b5 = { a4 c7 [2] 96 e5 [2] 90 d0 [2] be d0 [2] 81 cc }

  condition:
    any of them
}