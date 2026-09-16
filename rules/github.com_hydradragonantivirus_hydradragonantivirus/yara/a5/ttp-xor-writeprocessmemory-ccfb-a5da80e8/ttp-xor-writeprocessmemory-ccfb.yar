rule TTP_XOR_WriteProcessMemory_ccfb {
  strings:
    $key_ccfb = { 9b 89 [2] a9 ab [2] af 9e [2] 81 9e [2] be 82 }

  condition:
    any of them
}