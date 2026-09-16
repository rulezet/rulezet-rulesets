rule TTP_XOR_WriteProcessMemory_efe4 {
  strings:
    $key_efe4 = { b8 96 [2] 8a b4 [2] 8c 81 [2] a2 81 [2] 9d 9d }

  condition:
    any of them
}