rule TTP_XOR_WriteProcessMemory_dd1b {
  strings:
    $key_dd1b = { 8a 69 [2] b8 4b [2] be 7e [2] 90 7e [2] af 62 }

  condition:
    any of them
}