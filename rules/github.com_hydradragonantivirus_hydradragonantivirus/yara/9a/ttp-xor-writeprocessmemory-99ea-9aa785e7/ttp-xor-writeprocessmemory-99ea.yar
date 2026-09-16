rule TTP_XOR_WriteProcessMemory_99ea {
  strings:
    $key_99ea = { ce 98 [2] fc ba [2] fa 8f [2] d4 8f [2] eb 93 }

  condition:
    any of them
}