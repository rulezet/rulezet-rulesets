rule TTP_XOR_WriteProcessMemory_f34c {
  strings:
    $key_f34c = { a4 3e [2] 96 1c [2] 90 29 [2] be 29 [2] 81 35 }

  condition:
    any of them
}