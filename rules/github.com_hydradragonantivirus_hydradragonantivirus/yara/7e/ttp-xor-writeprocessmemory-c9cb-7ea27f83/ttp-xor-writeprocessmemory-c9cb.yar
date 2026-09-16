rule TTP_XOR_WriteProcessMemory_c9cb {
  strings:
    $key_c9cb = { 9e b9 [2] ac 9b [2] aa ae [2] 84 ae [2] bb b2 }

  condition:
    any of them
}