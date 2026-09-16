rule TTP_XOR_WriteProcessMemory_e27e {
  strings:
    $key_e27e = { b5 0c [2] 87 2e [2] 81 1b [2] af 1b [2] 90 07 }

  condition:
    any of them
}