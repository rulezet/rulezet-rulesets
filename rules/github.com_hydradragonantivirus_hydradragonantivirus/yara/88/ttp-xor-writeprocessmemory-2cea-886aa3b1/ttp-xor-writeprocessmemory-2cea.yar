rule TTP_XOR_WriteProcessMemory_2cea {
  strings:
    $key_2cea = { 7b 98 [2] 49 ba [2] 4f 8f [2] 61 8f [2] 5e 93 }

  condition:
    any of them
}