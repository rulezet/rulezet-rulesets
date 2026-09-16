rule TTP_XOR_WriteProcessMemory_a2fa {
  strings:
    $key_a2fa = { f5 88 [2] c7 aa [2] c1 9f [2] ef 9f [2] d0 83 }

  condition:
    any of them
}