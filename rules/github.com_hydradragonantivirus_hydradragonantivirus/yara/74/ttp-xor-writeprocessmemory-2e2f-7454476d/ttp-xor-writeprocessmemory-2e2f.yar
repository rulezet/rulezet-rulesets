rule TTP_XOR_WriteProcessMemory_2e2f {
  strings:
    $key_2e2f = { 79 5d [2] 4b 7f [2] 4d 4a [2] 63 4a [2] 5c 56 }

  condition:
    any of them
}