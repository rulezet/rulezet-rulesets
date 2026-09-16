rule TTP_XOR_WriteProcessMemory_f81b {
  strings:
    $key_f81b = { af 69 [2] 9d 4b [2] 9b 7e [2] b5 7e [2] 8a 62 }

  condition:
    any of them
}