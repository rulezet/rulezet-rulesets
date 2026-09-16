rule TTP_XOR_WriteProcessMemory_dd7f {
  strings:
    $key_dd7f = { 8a 0d [2] b8 2f [2] be 1a [2] 90 1a [2] af 06 }

  condition:
    any of them
}