rule TTP_XOR_WriteProcessMemory_126e {
  strings:
    $key_126e = { 45 1c [2] 77 3e [2] 71 0b [2] 5f 0b [2] 60 17 }

  condition:
    any of them
}