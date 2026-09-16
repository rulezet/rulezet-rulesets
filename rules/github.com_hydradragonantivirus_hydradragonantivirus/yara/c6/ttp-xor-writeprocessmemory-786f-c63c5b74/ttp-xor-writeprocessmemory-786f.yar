rule TTP_XOR_WriteProcessMemory_786f {
  strings:
    $key_786f = { 2f 1d [2] 1d 3f [2] 1b 0a [2] 35 0a [2] 0a 16 }

  condition:
    any of them
}