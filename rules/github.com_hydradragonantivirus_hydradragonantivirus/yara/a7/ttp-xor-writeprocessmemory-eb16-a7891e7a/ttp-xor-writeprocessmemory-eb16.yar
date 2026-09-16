rule TTP_XOR_WriteProcessMemory_eb16 {
  strings:
    $key_eb16 = { bc 64 [2] 8e 46 [2] 88 73 [2] a6 73 [2] 99 6f }

  condition:
    any of them
}