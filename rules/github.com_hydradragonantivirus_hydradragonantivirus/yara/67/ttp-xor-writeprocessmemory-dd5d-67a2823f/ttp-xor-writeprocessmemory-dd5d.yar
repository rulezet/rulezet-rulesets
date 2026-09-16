rule TTP_XOR_WriteProcessMemory_dd5d {
  strings:
    $key_dd5d = { 8a 2f [2] b8 0d [2] be 38 [2] 90 38 [2] af 24 }

  condition:
    any of them
}