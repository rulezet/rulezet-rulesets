rule TTP_XOR_WriteProcessMemory_0c2f {
  strings:
    $key_0c2f = { 5b 5d [2] 69 7f [2] 6f 4a [2] 41 4a [2] 7e 56 }

  condition:
    any of them
}