rule TTP_XOR_WriteProcessMemory_613e {
  strings:
    $key_613e = { 36 4c [2] 04 6e [2] 02 5b [2] 2c 5b [2] 13 47 }

  condition:
    any of them
}