rule TTP_XOR_WriteProcessMemory_94fa {
  strings:
    $key_94fa = { c3 88 [2] f1 aa [2] f7 9f [2] d9 9f [2] e6 83 }

  condition:
    any of them
}