rule TTP_XOR_WriteProcessMemory_80fa {
  strings:
    $key_80fa = { d7 88 [2] e5 aa [2] e3 9f [2] cd 9f [2] f2 83 }

  condition:
    any of them
}