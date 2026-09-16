rule TTP_XOR_WriteProcessMemory_6beb {
  strings:
    $key_6beb = { 3c 99 [2] 0e bb [2] 08 8e [2] 26 8e [2] 19 92 }

  condition:
    any of them
}