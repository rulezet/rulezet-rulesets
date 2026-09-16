rule TTP_XOR_WriteProcessMemory_8edf {
  strings:
    $key_8edf = { d9 ad [2] eb 8f [2] ed ba [2] c3 ba [2] fc a6 }

  condition:
    any of them
}