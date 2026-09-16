rule TTP_XOR_WriteProcessMemory_097e {
  strings:
    $key_097e = { 5e 0c [2] 6c 2e [2] 6a 1b [2] 44 1b [2] 7b 07 }

  condition:
    any of them
}