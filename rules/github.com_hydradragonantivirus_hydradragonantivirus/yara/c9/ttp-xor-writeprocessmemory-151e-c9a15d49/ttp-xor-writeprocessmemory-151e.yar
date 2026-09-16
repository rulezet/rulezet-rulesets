rule TTP_XOR_WriteProcessMemory_151e {
  strings:
    $key_151e = { 42 6c [2] 70 4e [2] 76 7b [2] 58 7b [2] 67 67 }

  condition:
    any of them
}