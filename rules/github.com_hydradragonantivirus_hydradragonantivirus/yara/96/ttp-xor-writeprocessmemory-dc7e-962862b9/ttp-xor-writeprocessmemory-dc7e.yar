rule TTP_XOR_WriteProcessMemory_dc7e {
  strings:
    $key_dc7e = { 8b 0c [2] b9 2e [2] bf 1b [2] 91 1b [2] ae 07 }

  condition:
    any of them
}