rule TTP_XOR_WriteProcessMemory_016e {
  strings:
    $key_016e = { 56 1c [2] 64 3e [2] 62 0b [2] 4c 0b [2] 73 17 }

  condition:
    any of them
}