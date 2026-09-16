rule TTP_XOR_WriteProcessMemory_217f {
  strings:
    $key_217f = { 76 0d [2] 44 2f [2] 42 1a [2] 6c 1a [2] 53 06 }

  condition:
    any of them
}