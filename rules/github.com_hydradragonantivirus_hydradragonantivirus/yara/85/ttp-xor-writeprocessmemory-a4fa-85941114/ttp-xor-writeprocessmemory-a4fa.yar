rule TTP_XOR_WriteProcessMemory_a4fa {
  strings:
    $key_a4fa = { f3 88 [2] c1 aa [2] c7 9f [2] e9 9f [2] d6 83 }

  condition:
    any of them
}