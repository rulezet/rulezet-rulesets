rule TTP_XOR_WriteProcessMemory_f8eb {
  strings:
    $key_f8eb = { af 99 [2] 9d bb [2] 9b 8e [2] b5 8e [2] 8a 92 }

  condition:
    any of them
}