rule TTP_XOR_WriteProcessMemory_e3dd {
  strings:
    $key_e3dd = { b4 af [2] 86 8d [2] 80 b8 [2] ae b8 [2] 91 a4 }

  condition:
    any of them
}