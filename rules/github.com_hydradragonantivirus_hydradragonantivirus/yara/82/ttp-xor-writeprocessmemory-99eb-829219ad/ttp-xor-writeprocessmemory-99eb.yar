rule TTP_XOR_WriteProcessMemory_99eb {
  strings:
    $key_99eb = { ce 99 [2] fc bb [2] fa 8e [2] d4 8e [2] eb 92 }

  condition:
    any of them
}