rule TTP_XOR_WriteProcessMemory_dd4c {
  strings:
    $key_dd4c = { 8a 3e [2] b8 1c [2] be 29 [2] 90 29 [2] af 35 }

  condition:
    any of them
}