rule TTP_XOR_WriteProcessMemory_ef2b {
  strings:
    $key_ef2b = { b8 59 [2] 8a 7b [2] 8c 4e [2] a2 4e [2] 9d 52 }

  condition:
    any of them
}