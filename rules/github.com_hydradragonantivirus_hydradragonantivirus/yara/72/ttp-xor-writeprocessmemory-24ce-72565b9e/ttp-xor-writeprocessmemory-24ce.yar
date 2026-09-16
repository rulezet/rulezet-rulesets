rule TTP_XOR_WriteProcessMemory_24ce {
  strings:
    $key_24ce = { 73 bc [2] 41 9e [2] 47 ab [2] 69 ab [2] 56 b7 }

  condition:
    any of them
}