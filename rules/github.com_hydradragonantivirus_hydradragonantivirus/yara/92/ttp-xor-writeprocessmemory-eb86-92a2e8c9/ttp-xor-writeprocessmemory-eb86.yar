rule TTP_XOR_WriteProcessMemory_eb86 {
  strings:
    $key_eb86 = { bc f4 [2] 8e d6 [2] 88 e3 [2] a6 e3 [2] 99 ff }

  condition:
    any of them
}