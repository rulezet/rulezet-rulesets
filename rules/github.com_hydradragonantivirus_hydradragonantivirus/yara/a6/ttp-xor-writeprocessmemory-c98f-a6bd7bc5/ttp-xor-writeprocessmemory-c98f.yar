rule TTP_XOR_WriteProcessMemory_c98f {
  strings:
    $key_c98f = { 9e fd [2] ac df [2] aa ea [2] 84 ea [2] bb f6 }

  condition:
    any of them
}