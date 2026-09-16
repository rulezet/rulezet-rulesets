rule TTP_XOR_WriteProcessMemory_b23c {
  strings:
    $key_b23c = { e5 4e [2] d7 6c [2] d1 59 [2] ff 59 [2] c0 45 }

  condition:
    any of them
}