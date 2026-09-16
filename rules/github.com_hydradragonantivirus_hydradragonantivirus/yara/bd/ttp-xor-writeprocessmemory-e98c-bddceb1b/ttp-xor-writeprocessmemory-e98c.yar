rule TTP_XOR_WriteProcessMemory_e98c {
  strings:
    $key_e98c = { be fe [2] 8c dc [2] 8a e9 [2] a4 e9 [2] 9b f5 }

  condition:
    any of them
}