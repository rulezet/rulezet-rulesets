rule TTP_XOR_WriteProcessMemory_eef1 {
  strings:
    $key_eef1 = { b9 83 [2] 8b a1 [2] 8d 94 [2] a3 94 [2] 9c 88 }

  condition:
    any of them
}