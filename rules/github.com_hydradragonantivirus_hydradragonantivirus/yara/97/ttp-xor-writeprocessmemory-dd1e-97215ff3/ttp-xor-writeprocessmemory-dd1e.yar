rule TTP_XOR_WriteProcessMemory_dd1e {
  strings:
    $key_dd1e = { 8a 6c [2] b8 4e [2] be 7b [2] 90 7b [2] af 67 }

  condition:
    any of them
}