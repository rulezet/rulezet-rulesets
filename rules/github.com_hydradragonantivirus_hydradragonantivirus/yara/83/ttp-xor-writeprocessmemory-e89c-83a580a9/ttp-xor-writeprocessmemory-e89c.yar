rule TTP_XOR_WriteProcessMemory_e89c {
  strings:
    $key_e89c = { bf ee [2] 8d cc [2] 8b f9 [2] a5 f9 [2] 9a e5 }

  condition:
    any of them
}