rule TTP_XOR_WriteProcessMemory_dd6c {
  strings:
    $key_dd6c = { 8a 1e [2] b8 3c [2] be 09 [2] 90 09 [2] af 15 }

  condition:
    any of them
}