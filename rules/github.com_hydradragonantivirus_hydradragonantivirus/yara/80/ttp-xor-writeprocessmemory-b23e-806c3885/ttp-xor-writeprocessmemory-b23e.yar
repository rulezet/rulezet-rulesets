rule TTP_XOR_WriteProcessMemory_b23e {
  strings:
    $key_b23e = { e5 4c [2] d7 6e [2] d1 5b [2] ff 5b [2] c0 47 }

  condition:
    any of them
}