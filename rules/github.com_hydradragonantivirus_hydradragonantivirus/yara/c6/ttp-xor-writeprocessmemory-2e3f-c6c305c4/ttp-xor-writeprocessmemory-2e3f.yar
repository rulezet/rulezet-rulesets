rule TTP_XOR_WriteProcessMemory_2e3f {
  strings:
    $key_2e3f = { 79 4d [2] 4b 6f [2] 4d 5a [2] 63 5a [2] 5c 46 }

  condition:
    any of them
}