rule TTP_XOR_WriteProcessMemory_b3fa {
  strings:
    $key_b3fa = { e4 88 [2] d6 aa [2] d0 9f [2] fe 9f [2] c1 83 }

  condition:
    any of them
}