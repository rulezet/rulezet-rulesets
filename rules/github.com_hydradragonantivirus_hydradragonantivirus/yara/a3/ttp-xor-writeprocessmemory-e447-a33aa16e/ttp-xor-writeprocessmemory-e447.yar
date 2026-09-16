rule TTP_XOR_WriteProcessMemory_e447 {
  strings:
    $key_e447 = { b3 35 [2] 81 17 [2] 87 22 [2] a9 22 [2] 96 3e }

  condition:
    any of them
}