rule TTP_XOR_WriteProcessMemory_eaa2 {
  strings:
    $key_eaa2 = { bd d0 [2] 8f f2 [2] 89 c7 [2] a7 c7 [2] 98 db }

  condition:
    any of them
}