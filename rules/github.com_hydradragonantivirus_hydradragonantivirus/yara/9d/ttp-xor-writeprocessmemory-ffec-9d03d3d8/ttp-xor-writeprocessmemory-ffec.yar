rule TTP_XOR_WriteProcessMemory_ffec {
  strings:
    $key_ffec = { a8 9e [2] 9a bc [2] 9c 89 [2] b2 89 [2] 8d 95 }

  condition:
    any of them
}