rule TTP_XOR_WriteProcessMemory_ef6e {
  strings:
    $key_ef6e = { b8 1c [2] 8a 3e [2] 8c 0b [2] a2 0b [2] 9d 17 }

  condition:
    any of them
}