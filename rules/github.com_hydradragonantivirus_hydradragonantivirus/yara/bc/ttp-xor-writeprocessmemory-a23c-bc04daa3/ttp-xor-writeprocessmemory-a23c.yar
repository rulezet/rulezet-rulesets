rule TTP_XOR_WriteProcessMemory_a23c {
  strings:
    $key_a23c = { f5 4e [2] c7 6c [2] c1 59 [2] ef 59 [2] d0 45 }

  condition:
    any of them
}