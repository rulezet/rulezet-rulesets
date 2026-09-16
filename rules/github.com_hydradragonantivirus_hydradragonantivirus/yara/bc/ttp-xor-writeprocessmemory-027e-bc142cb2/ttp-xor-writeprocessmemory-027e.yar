rule TTP_XOR_WriteProcessMemory_027e {
  strings:
    $key_027e = { 55 0c [2] 67 2e [2] 61 1b [2] 4f 1b [2] 70 07 }

  condition:
    any of them
}