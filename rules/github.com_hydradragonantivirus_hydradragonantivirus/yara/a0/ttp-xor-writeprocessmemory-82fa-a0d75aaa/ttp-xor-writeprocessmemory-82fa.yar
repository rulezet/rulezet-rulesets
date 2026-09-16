rule TTP_XOR_WriteProcessMemory_82fa {
  strings:
    $key_82fa = { d5 88 [2] e7 aa [2] e1 9f [2] cf 9f [2] f0 83 }

  condition:
    any of them
}