rule TTP_XOR_WriteProcessMemory_65ed {
  strings:
    $key_65ed = { 32 9f [2] 00 bd [2] 06 88 [2] 28 88 [2] 17 94 }

  condition:
    any of them
}