rule TTP_XOR_WriteProcessMemory_4f7e {
  strings:
    $key_4f7e = { 18 0c [2] 2a 2e [2] 2c 1b [2] 02 1b [2] 3d 07 }

  condition:
    any of them
}