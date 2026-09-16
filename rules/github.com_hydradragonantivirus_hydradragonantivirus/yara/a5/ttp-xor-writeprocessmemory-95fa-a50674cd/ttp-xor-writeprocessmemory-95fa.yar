rule TTP_XOR_WriteProcessMemory_95fa {
  strings:
    $key_95fa = { c2 88 [2] f0 aa [2] f6 9f [2] d8 9f [2] e7 83 }

  condition:
    any of them
}