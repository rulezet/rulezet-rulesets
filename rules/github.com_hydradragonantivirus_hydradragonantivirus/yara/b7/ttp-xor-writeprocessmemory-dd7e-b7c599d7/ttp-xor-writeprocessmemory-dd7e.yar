rule TTP_XOR_WriteProcessMemory_dd7e {
  strings:
    $key_dd7e = { 8a 0c [2] b8 2e [2] be 1b [2] 90 1b [2] af 07 }

  condition:
    any of them
}