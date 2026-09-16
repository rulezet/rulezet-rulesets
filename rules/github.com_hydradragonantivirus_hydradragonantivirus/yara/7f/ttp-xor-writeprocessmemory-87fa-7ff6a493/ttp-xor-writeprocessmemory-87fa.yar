rule TTP_XOR_WriteProcessMemory_87fa {
  strings:
    $key_87fa = { d0 88 [2] e2 aa [2] e4 9f [2] ca 9f [2] f5 83 }

  condition:
    any of them
}