rule TTP_XOR_WriteProcessMemory_698f {
  strings:
    $key_698f = { 3e fd [2] 0c df [2] 0a ea [2] 24 ea [2] 1b f6 }

  condition:
    any of them
}