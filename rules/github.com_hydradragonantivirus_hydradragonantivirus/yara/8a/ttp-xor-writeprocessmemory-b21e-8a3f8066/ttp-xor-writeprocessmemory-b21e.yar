rule TTP_XOR_WriteProcessMemory_b21e {
  strings:
    $key_b21e = { e5 6c [2] d7 4e [2] d1 7b [2] ff 7b [2] c0 67 }

  condition:
    any of them
}