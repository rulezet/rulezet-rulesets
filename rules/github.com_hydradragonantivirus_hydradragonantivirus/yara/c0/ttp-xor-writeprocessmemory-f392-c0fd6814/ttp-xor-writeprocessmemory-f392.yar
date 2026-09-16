rule TTP_XOR_WriteProcessMemory_f392 {
  strings:
    $key_f392 = { a4 e0 [2] 96 c2 [2] 90 f7 [2] be f7 [2] 81 eb }

  condition:
    any of them
}