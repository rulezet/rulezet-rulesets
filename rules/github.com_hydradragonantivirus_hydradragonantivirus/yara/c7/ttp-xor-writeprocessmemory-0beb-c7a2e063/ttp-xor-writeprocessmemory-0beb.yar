rule TTP_XOR_WriteProcessMemory_0beb {
  strings:
    $key_0beb = { 5c 99 [2] 6e bb [2] 68 8e [2] 46 8e [2] 79 92 }

  condition:
    any of them
}