rule TTP_XOR_WriteProcessMemory_752c {
  strings:
    $key_752c = { 22 5e [2] 10 7c [2] 16 49 [2] 38 49 [2] 07 55 }

  condition:
    any of them
}