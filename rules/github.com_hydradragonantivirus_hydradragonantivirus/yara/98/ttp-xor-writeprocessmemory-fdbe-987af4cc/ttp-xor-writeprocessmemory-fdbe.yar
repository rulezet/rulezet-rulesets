rule TTP_XOR_WriteProcessMemory_fdbe {
  strings:
    $key_fdbe = { aa cc [2] 98 ee [2] 9e db [2] b0 db [2] 8f c7 }

  condition:
    any of them
}