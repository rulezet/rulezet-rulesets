rule TTP_XOR_WriteProcessMemory_ffeb {
  strings:
    $key_ffeb = { a8 99 [2] 9a bb [2] 9c 8e [2] b2 8e [2] 8d 92 }

  condition:
    any of them
}