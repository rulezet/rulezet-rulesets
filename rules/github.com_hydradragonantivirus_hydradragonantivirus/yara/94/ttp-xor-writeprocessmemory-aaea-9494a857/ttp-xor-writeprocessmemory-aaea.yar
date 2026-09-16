rule TTP_XOR_WriteProcessMemory_aaea {
  strings:
    $key_aaea = { fd 98 [2] cf ba [2] c9 8f [2] e7 8f [2] d8 93 }

  condition:
    any of them
}