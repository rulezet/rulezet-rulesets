rule TTP_XOR_WriteProcessMemory_601e {
  strings:
    $key_601e = { 37 6c [2] 05 4e [2] 03 7b [2] 2d 7b [2] 12 67 }

  condition:
    any of them
}