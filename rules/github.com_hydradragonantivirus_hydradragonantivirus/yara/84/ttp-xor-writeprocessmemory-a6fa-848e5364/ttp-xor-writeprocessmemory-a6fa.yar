rule TTP_XOR_WriteProcessMemory_a6fa {
  strings:
    $key_a6fa = { f1 88 [2] c3 aa [2] c5 9f [2] eb 9f [2] d4 83 }

  condition:
    any of them
}