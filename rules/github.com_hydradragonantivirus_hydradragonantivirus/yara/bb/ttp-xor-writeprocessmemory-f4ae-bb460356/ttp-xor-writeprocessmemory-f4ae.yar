rule TTP_XOR_WriteProcessMemory_f4ae {
  strings:
    $key_f4ae = { a3 dc [2] 91 fe [2] 97 cb [2] b9 cb [2] 86 d7 }

  condition:
    any of them
}