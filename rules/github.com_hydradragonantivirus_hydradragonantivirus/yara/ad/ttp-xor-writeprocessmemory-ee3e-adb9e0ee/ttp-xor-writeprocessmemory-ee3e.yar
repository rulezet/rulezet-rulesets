rule TTP_XOR_WriteProcessMemory_ee3e {
  strings:
    $key_ee3e = { b9 4c [2] 8b 6e [2] 8d 5b [2] a3 5b [2] 9c 47 }

  condition:
    any of them
}