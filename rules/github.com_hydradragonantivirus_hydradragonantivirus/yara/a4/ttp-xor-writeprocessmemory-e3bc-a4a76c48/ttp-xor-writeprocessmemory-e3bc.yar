rule TTP_XOR_WriteProcessMemory_e3bc {
  strings:
    $key_e3bc = { b4 ce [2] 86 ec [2] 80 d9 [2] ae d9 [2] 91 c5 }

  condition:
    any of them
}