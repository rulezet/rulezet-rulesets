rule TTP_XOR_WriteProcessMemory_e87b {
  strings:
    $key_e87b = { bf 09 [2] 8d 2b [2] 8b 1e [2] a5 1e [2] 9a 02 }

  condition:
    any of them
}