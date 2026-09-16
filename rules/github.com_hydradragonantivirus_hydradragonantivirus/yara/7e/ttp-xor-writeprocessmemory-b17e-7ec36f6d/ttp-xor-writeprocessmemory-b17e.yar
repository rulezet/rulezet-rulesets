rule TTP_XOR_WriteProcessMemory_b17e {
  strings:
    $key_b17e = { e6 0c [2] d4 2e [2] d2 1b [2] fc 1b [2] c3 07 }

  condition:
    any of them
}