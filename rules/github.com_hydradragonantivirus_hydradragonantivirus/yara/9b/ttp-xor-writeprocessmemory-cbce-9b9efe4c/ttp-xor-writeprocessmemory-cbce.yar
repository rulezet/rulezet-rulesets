rule TTP_XOR_WriteProcessMemory_cbce {
  strings:
    $key_cbce = { 9c bc [2] ae 9e [2] a8 ab [2] 86 ab [2] b9 b7 }

  condition:
    any of them
}