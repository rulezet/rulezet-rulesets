rule TTP_XOR_WriteProcessMemory_99bf {
  strings:
    $key_99bf = { ce cd [2] fc ef [2] fa da [2] d4 da [2] eb c6 }

  condition:
    any of them
}