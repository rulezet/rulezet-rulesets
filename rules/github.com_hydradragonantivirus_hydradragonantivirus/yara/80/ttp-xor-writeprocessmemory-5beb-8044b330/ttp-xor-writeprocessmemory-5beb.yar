rule TTP_XOR_WriteProcessMemory_5beb {
  strings:
    $key_5beb = { 0c 99 [2] 3e bb [2] 38 8e [2] 16 8e [2] 29 92 }

  condition:
    any of them
}