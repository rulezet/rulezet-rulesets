rule TTP_XOR_WriteProcessMemory_297b {
  strings:
    $key_297b = { 7e 09 [2] 4c 2b [2] 4a 1e [2] 64 1e [2] 5b 02 }

  condition:
    any of them
}