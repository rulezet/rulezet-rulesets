rule TTP_XOR_WriteProcessMemory_fdec {
  strings:
    $key_fdec = { aa 9e [2] 98 bc [2] 9e 89 [2] b0 89 [2] 8f 95 }

  condition:
    any of them
}