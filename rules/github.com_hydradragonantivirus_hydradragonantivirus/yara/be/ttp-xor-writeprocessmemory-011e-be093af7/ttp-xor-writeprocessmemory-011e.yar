rule TTP_XOR_WriteProcessMemory_011e {
  strings:
    $key_011e = { 56 6c [2] 64 4e [2] 62 7b [2] 4c 7b [2] 73 67 }

  condition:
    any of them
}