rule TTP_XOR_WriteProcessMemory_f98f {
  strings:
    $key_f98f = { ae fd [2] 9c df [2] 9a ea [2] b4 ea [2] 8b f6 }

  condition:
    any of them
}