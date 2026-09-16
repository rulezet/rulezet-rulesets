rule TTP_XOR_WriteProcessMemory_eba4 {
  strings:
    $key_eba4 = { bc d6 [2] 8e f4 [2] 88 c1 [2] a6 c1 [2] 99 dd }

  condition:
    any of them
}