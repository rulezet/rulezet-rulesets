rule TTP_XOR_WriteProcessMemory_0c3e {
  strings:
    $key_0c3e = { 5b 4c [2] 69 6e [2] 6f 5b [2] 41 5b [2] 7e 47 }

  condition:
    any of them
}