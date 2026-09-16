rule TTP_XOR_WriteProcessMemory_705c {
  strings:
    $key_705c = { 27 2e [2] 15 0c [2] 13 39 [2] 3d 39 [2] 02 25 }

  condition:
    any of them
}