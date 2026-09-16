rule TTP_XOR_WriteProcessMemory_85fa {
  strings:
    $key_85fa = { d2 88 [2] e0 aa [2] e6 9f [2] c8 9f [2] f7 83 }

  condition:
    any of them
}