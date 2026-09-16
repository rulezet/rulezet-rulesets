rule TTP_XOR_WriteProcessMemory_280f {
  strings:
    $key_280f = { 7f 7d [2] 4d 5f [2] 4b 6a [2] 65 6a [2] 5a 76 }

  condition:
    any of them
}