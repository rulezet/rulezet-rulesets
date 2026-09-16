rule TTP_XOR_WriteProcessMemory_dd5c {
  strings:
    $key_dd5c = { 8a 2e [2] b8 0c [2] be 39 [2] 90 39 [2] af 25 }

  condition:
    any of them
}