rule TTP_XOR_WriteProcessMemory_3beb {
  strings:
    $key_3beb = { 6c 99 [2] 5e bb [2] 58 8e [2] 76 8e [2] 49 92 }

  condition:
    any of them
}