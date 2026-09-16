rule TTP_XOR_WriteProcessMemory_ddff {
  strings:
    $key_ddff = { 8a 8d [2] b8 af [2] be 9a [2] 90 9a [2] af 86 }

  condition:
    any of them
}