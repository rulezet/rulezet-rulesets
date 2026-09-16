rule TTP_XOR_WriteProcessMemory_ef4c {
  strings:
    $key_ef4c = { b8 3e [2] 8a 1c [2] 8c 29 [2] a2 29 [2] 9d 35 }

  condition:
    any of them
}