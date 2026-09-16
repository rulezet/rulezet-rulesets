rule TTP_XOR_WriteProcessMemory_ee3b {
  strings:
    $key_ee3b = { b9 49 [2] 8b 6b [2] 8d 5e [2] a3 5e [2] 9c 42 }

  condition:
    any of them
}