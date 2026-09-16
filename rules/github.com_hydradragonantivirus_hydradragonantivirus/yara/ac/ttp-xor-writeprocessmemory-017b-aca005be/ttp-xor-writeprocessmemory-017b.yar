rule TTP_XOR_WriteProcessMemory_017b {
  strings:
    $key_017b = { 56 09 [2] 64 2b [2] 62 1e [2] 4c 1e [2] 73 02 }

  condition:
    any of them
}