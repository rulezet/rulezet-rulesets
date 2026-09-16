rule TTP_XOR_WriteProcessMemory_eb34 {
  strings:
    $key_eb34 = { bc 46 [2] 8e 64 [2] 88 51 [2] a6 51 [2] 99 4d }

  condition:
    any of them
}