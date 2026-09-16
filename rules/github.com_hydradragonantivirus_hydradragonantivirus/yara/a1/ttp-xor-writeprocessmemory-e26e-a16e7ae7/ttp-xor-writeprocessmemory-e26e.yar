rule TTP_XOR_WriteProcessMemory_e26e {
  strings:
    $key_e26e = { b5 1c [2] 87 3e [2] 81 0b [2] af 0b [2] 90 17 }

  condition:
    any of them
}