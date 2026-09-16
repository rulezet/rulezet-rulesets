rule TTP_XOR_WriteProcessMemory_0c1e {
  strings:
    $key_0c1e = { 5b 6c [2] 69 4e [2] 6f 7b [2] 41 7b [2] 7e 67 }

  condition:
    any of them
}