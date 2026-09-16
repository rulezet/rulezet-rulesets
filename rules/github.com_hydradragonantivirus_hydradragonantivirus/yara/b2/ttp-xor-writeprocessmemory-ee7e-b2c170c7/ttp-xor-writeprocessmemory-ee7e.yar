rule TTP_XOR_WriteProcessMemory_ee7e {
  strings:
    $key_ee7e = { b9 0c [2] 8b 2e [2] 8d 1b [2] a3 1b [2] 9c 07 }

  condition:
    any of them
}