rule TTP_XOR_WriteProcessMemory_99ff {
  strings:
    $key_99ff = { ce 8d [2] fc af [2] fa 9a [2] d4 9a [2] eb 86 }

  condition:
    any of them
}