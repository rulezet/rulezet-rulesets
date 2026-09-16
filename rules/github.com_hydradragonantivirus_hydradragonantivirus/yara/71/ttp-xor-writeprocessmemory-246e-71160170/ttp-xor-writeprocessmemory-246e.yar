rule TTP_XOR_WriteProcessMemory_246e {
  strings:
    $key_246e = { 73 1c [2] 41 3e [2] 47 0b [2] 69 0b [2] 56 17 }

  condition:
    any of them
}