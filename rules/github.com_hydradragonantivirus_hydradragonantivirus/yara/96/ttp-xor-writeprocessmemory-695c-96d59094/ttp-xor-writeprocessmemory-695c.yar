rule TTP_XOR_WriteProcessMemory_695c {
  strings:
    $key_695c = { 3e 2e [2] 0c 0c [2] 0a 39 [2] 24 39 [2] 1b 25 }

  condition:
    any of them
}