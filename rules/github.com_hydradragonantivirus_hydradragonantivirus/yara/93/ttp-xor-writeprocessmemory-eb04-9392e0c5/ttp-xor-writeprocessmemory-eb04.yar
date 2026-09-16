rule TTP_XOR_WriteProcessMemory_eb04 {
  strings:
    $key_eb04 = { bc 76 [2] 8e 54 [2] 88 61 [2] a6 61 [2] 99 7d }

  condition:
    any of them
}