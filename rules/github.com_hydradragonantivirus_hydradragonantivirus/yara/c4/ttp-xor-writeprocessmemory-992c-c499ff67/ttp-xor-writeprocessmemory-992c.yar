rule TTP_XOR_WriteProcessMemory_992c {
  strings:
    $key_992c = { ce 5e [2] fc 7c [2] fa 49 [2] d4 49 [2] eb 55 }

  condition:
    any of them
}