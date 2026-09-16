rule TTP_XOR_WriteProcessMemory_298f {
  strings:
    $key_298f = { 7e fd [2] 4c df [2] 4a ea [2] 64 ea [2] 5b f6 }

  condition:
    any of them
}