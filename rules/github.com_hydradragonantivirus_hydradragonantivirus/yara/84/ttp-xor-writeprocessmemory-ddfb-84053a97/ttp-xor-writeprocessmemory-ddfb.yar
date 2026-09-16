rule TTP_XOR_WriteProcessMemory_ddfb {
  strings:
    $key_ddfb = { 8a 89 [2] b8 ab [2] be 9e [2] 90 9e [2] af 82 }

  condition:
    any of them
}