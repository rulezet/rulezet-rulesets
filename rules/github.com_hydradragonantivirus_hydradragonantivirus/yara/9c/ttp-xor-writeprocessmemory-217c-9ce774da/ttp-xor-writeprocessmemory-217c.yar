rule TTP_XOR_WriteProcessMemory_217c {
  strings:
    $key_217c = { 76 0e [2] 44 2c [2] 42 19 [2] 6c 19 [2] 53 05 }

  condition:
    any of them
}