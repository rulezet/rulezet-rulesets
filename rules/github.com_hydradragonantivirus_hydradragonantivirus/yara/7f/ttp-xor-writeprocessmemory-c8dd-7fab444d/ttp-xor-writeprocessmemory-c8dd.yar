rule TTP_XOR_WriteProcessMemory_c8dd {
  strings:
    $key_c8dd = { 9f af [2] ad 8d [2] ab b8 [2] 85 b8 [2] ba a4 }

  condition:
    any of them
}