rule TTP_XOR_WriteProcessMemory_994b {
  strings:
    $key_994b = { ce 39 [2] fc 1b [2] fa 2e [2] d4 2e [2] eb 32 }

  condition:
    any of them
}