rule TTP_XOR_WriteProcessMemory_ee2e {
  strings:
    $key_ee2e = { b9 5c [2] 8b 7e [2] 8d 4b [2] a3 4b [2] 9c 57 }

  condition:
    any of them
}