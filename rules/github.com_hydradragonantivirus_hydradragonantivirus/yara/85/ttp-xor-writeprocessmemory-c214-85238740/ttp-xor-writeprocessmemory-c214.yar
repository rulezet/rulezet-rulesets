rule TTP_XOR_WriteProcessMemory_c214 {
  strings:
    $key_c214 = { 95 66 [2] a7 44 [2] a1 71 [2] 8f 71 [2] b0 6d }

  condition:
    any of them
}