rule TTP_XOR_WriteProcessMemory_eb14 {
  strings:
    $key_eb14 = { bc 66 [2] 8e 44 [2] 88 71 [2] a6 71 [2] 99 6d }

  condition:
    any of them
}