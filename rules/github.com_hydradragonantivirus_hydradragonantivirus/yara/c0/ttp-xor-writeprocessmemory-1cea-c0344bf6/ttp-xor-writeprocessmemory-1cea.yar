rule TTP_XOR_WriteProcessMemory_1cea {
  strings:
    $key_1cea = { 4b 98 [2] 79 ba [2] 7f 8f [2] 51 8f [2] 6e 93 }

  condition:
    any of them
}