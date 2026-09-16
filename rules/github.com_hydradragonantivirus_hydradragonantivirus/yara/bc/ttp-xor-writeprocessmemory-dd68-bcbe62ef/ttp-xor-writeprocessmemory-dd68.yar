rule TTP_XOR_WriteProcessMemory_dd68 {
  strings:
    $key_dd68 = { 8a 1a [2] b8 38 [2] be 0d [2] 90 0d [2] af 11 }

  condition:
    any of them
}