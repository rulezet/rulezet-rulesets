rule TTP_XOR_WriteProcessMemory_b26e {
  strings:
    $key_b26e = { e5 1c [2] d7 3e [2] d1 0b [2] ff 0b [2] c0 17 }

  condition:
    any of them
}