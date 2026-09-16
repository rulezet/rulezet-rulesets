rule TTP_XOR_WriteProcessMemory_613c {
  strings:
    $key_613c = { 36 4e [2] 04 6c [2] 02 59 [2] 2c 59 [2] 13 45 }

  condition:
    any of them
}