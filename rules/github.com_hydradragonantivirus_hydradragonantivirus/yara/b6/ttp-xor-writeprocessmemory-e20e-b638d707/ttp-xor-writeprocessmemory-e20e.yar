rule TTP_XOR_WriteProcessMemory_e20e {
  strings:
    $key_e20e = { b5 7c [2] 87 5e [2] 81 6b [2] af 6b [2] 90 77 }

  condition:
    any of them
}