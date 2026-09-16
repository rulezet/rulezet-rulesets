rule TTP_XOR_WriteProcessMemory_662f {
  strings:
    $key_662f = { 31 5d [2] 03 7f [2] 05 4a [2] 2b 4a [2] 14 56 }

  condition:
    any of them
}