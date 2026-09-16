rule TTP_XOR_WriteProcessMemory_212e {
  strings:
    $key_212e = { 76 5c [2] 44 7e [2] 42 4b [2] 6c 4b [2] 53 57 }

  condition:
    any of them
}