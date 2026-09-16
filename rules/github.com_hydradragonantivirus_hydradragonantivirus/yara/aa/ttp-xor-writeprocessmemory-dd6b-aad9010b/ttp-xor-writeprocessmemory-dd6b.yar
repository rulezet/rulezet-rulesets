rule TTP_XOR_WriteProcessMemory_dd6b {
  strings:
    $key_dd6b = { 8a 19 [2] b8 3b [2] be 0e [2] 90 0e [2] af 12 }

  condition:
    any of them
}