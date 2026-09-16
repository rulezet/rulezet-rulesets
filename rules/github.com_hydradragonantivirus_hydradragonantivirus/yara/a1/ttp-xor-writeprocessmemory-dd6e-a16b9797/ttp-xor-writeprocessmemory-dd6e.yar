rule TTP_XOR_WriteProcessMemory_dd6e {
  strings:
    $key_dd6e = { 8a 1c [2] b8 3e [2] be 0b [2] 90 0b [2] af 17 }

  condition:
    any of them
}