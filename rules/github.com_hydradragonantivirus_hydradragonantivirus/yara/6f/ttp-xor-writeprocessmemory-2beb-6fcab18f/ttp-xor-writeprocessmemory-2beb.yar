rule TTP_XOR_WriteProcessMemory_2beb {
  strings:
    $key_2beb = { 7c 99 [2] 4e bb [2] 48 8e [2] 66 8e [2] 59 92 }

  condition:
    any of them
}