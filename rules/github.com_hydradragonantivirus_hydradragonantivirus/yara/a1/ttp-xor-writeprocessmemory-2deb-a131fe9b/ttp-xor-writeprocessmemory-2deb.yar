rule TTP_XOR_WriteProcessMemory_2deb {
  strings:
    $key_2deb = { 7a 99 [2] 48 bb [2] 4e 8e [2] 60 8e [2] 5f 92 }

  condition:
    any of them
}