rule TTP_XOR_WriteProcessMemory_e24e {
  strings:
    $key_e24e = { b5 3c [2] 87 1e [2] 81 2b [2] af 2b [2] 90 37 }

  condition:
    any of them
}