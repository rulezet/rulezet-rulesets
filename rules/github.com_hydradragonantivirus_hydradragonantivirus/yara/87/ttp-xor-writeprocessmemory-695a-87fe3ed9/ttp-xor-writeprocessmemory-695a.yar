rule TTP_XOR_WriteProcessMemory_695a {
  strings:
    $key_695a = { 3e 28 [2] 0c 0a [2] 0a 3f [2] 24 3f [2] 1b 23 }

  condition:
    any of them
}