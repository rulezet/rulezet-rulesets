rule TTP_XOR_WriteProcessMemory_1e2f {
  strings:
    $key_1e2f = { 49 5d [2] 7b 7f [2] 7d 4a [2] 53 4a [2] 6c 56 }

  condition:
    any of them
}