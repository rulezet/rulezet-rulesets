rule TTP_XOR_WriteProcessMemory_dd7c {
  strings:
    $key_dd7c = { 8a 0e [2] b8 2c [2] be 19 [2] 90 19 [2] af 05 }

  condition:
    any of them
}