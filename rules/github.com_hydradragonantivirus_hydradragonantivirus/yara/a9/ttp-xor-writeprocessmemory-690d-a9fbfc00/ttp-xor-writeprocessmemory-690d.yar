rule TTP_XOR_WriteProcessMemory_690d {
  strings:
    $key_690d = { 3e 7f [2] 0c 5d [2] 0a 68 [2] 24 68 [2] 1b 74 }

  condition:
    any of them
}