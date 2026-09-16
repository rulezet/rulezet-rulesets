rule TTP_XOR_WriteProcessMemory_dceb {
  strings:
    $key_dceb = { 8b 99 [2] b9 bb [2] bf 8e [2] 91 8e [2] ae 92 }

  condition:
    any of them
}