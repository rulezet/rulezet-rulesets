rule TTP_XOR_WriteProcessMemory_e23b {
  strings:
    $key_e23b = { b5 49 [2] 87 6b [2] 81 5e [2] af 5e [2] 90 42 }

  condition:
    any of them
}