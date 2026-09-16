rule TTP_XOR_WriteProcessMemory_ebeb {
  strings:
    $key_ebeb = { bc 99 [2] 8e bb [2] 88 8e [2] a6 8e [2] 99 92 }

  condition:
    any of them
}