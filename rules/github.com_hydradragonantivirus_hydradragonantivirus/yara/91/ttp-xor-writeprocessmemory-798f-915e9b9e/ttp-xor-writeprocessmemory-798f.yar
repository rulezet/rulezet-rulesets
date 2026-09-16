rule TTP_XOR_WriteProcessMemory_798f {
  strings:
    $key_798f = { 2e fd [2] 1c df [2] 1a ea [2] 34 ea [2] 0b f6 }

  condition:
    any of them
}