rule TTP_XOR_WriteProcessMemory_ee1e {
  strings:
    $key_ee1e = { b9 6c [2] 8b 4e [2] 8d 7b [2] a3 7b [2] 9c 67 }

  condition:
    any of them
}