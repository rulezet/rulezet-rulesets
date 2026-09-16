rule TTP_XOR_WriteProcessMemory_c217 {
  strings:
    $key_c217 = { 95 65 [2] a7 47 [2] a1 72 [2] 8f 72 [2] b0 6e }

  condition:
    any of them
}