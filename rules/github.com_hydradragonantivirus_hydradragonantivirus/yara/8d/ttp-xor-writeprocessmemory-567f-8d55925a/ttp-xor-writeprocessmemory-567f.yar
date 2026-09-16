rule TTP_XOR_WriteProcessMemory_567f {
  strings:
    $key_567f = { 01 0d [2] 33 2f [2] 35 1a [2] 1b 1a [2] 24 06 }

  condition:
    any of them
}