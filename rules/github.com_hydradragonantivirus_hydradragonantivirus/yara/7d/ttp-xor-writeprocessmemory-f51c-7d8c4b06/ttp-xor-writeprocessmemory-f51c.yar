rule TTP_XOR_WriteProcessMemory_f51c {
  strings:
    $key_f51c = { a2 6e [2] 90 4c [2] 96 79 [2] b8 79 [2] 87 65 }

  condition:
    any of them
}