rule TTP_XOR_WriteProcessMemory_592f {
  strings:
    $key_592f = { 0e 5d [2] 3c 7f [2] 3a 4a [2] 14 4a [2] 2b 56 }

  condition:
    any of them
}