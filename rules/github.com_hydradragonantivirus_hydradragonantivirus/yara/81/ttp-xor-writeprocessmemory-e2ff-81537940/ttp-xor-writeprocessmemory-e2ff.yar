rule TTP_XOR_WriteProcessMemory_e2ff {
  strings:
    $key_e2ff = { b5 8d [2] 87 af [2] 81 9a [2] af 9a [2] 90 86 }

  condition:
    any of them
}