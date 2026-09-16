rule TTP_XOR_WriteProcessMemory_96d8 {
  strings:
    $key_96d8 = { c1 aa [2] f3 88 [2] f5 bd [2] db bd [2] e4 a1 }

  condition:
    any of them
}