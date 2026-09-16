rule TTP_XOR_WriteProcessMemory_ee5b {
  strings:
    $key_ee5b = { b9 29 [2] 8b 0b [2] 8d 3e [2] a3 3e [2] 9c 22 }

  condition:
    any of them
}