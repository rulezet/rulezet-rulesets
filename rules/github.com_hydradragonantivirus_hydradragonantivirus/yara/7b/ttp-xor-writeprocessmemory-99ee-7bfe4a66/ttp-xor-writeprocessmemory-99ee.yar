rule TTP_XOR_WriteProcessMemory_99ee {
  strings:
    $key_99ee = { ce 9c [2] fc be [2] fa 8b [2] d4 8b [2] eb 97 }

  condition:
    any of them
}