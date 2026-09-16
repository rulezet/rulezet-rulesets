rule TTP_XOR_WriteProcessMemory_b8ff {
  strings:
    $key_b8ff = { ef 8d [2] dd af [2] db 9a [2] f5 9a [2] ca 86 }

  condition:
    any of them
}