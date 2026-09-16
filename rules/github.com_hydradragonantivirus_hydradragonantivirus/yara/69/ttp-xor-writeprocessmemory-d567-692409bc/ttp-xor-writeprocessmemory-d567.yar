rule TTP_XOR_WriteProcessMemory_d567 {
  strings:
    $key_d567 = { 82 15 [2] b0 37 [2] b6 02 [2] 98 02 [2] a7 1e }

  condition:
    any of them
}