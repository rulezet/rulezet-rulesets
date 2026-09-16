rule TTP_XOR_WriteProcessMemory_1e1f {
  strings:
    $key_1e1f = { 49 6d [2] 7b 4f [2] 7d 7a [2] 53 7a [2] 6c 66 }

  condition:
    any of them
}