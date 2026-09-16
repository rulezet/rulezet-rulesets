rule TTP_XOR_WriteProcessMemory_6cea {
  strings:
    $key_6cea = { 3b 98 [2] 09 ba [2] 0f 8f [2] 21 8f [2] 1e 93 }

  condition:
    any of them
}