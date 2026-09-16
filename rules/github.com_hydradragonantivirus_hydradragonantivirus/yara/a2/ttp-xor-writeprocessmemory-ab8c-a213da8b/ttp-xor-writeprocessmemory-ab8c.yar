rule TTP_XOR_WriteProcessMemory_ab8c {
  strings:
    $key_ab8c = { fc fe [2] ce dc [2] c8 e9 [2] e6 e9 [2] d9 f5 }

  condition:
    any of them
}