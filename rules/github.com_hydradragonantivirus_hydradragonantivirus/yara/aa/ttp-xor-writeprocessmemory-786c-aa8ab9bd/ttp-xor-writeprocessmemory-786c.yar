rule TTP_XOR_WriteProcessMemory_786c {
  strings:
    $key_786c = { 2f 1e [2] 1d 3c [2] 1b 09 [2] 35 09 [2] 0a 15 }

  condition:
    any of them
}