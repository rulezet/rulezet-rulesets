rule TTP_XOR_WriteProcessMemory_efe2 {
  strings:
    $key_efe2 = { b8 90 [2] 8a b2 [2] 8c 87 [2] a2 87 [2] 9d 9b }

  condition:
    any of them
}