rule TTP_XOR_WriteProcessMemory_e87e {
  strings:
    $key_e87e = { bf 0c [2] 8d 2e [2] 8b 1b [2] a5 1b [2] 9a 07 }

  condition:
    any of them
}