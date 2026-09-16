rule TTP_XOR_WriteProcessMemory_996c {
  strings:
    $key_996c = { ce 1e [2] fc 3c [2] fa 09 [2] d4 09 [2] eb 15 }

  condition:
    any of them
}