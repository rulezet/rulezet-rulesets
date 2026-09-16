rule TTP_XOR_WriteProcessMemory_e417 {
  strings:
    $key_e417 = { b3 65 [2] 81 47 [2] 87 72 [2] a9 72 [2] 96 6e }

  condition:
    any of them
}