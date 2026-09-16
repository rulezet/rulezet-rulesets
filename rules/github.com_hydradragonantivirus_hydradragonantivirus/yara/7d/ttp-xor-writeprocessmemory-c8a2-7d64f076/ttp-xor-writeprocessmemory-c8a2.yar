rule TTP_XOR_WriteProcessMemory_c8a2 {
  strings:
    $key_c8a2 = { 9f d0 [2] ad f2 [2] ab c7 [2] 85 c7 [2] ba db }

  condition:
    any of them
}