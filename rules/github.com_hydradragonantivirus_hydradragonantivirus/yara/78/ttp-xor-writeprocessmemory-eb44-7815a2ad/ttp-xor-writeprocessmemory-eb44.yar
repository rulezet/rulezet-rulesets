rule TTP_XOR_WriteProcessMemory_eb44 {
  strings:
    $key_eb44 = { bc 36 [2] 8e 14 [2] 88 21 [2] a6 21 [2] 99 3d }

  condition:
    any of them
}