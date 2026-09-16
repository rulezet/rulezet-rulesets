rule TTP_XOR_WriteProcessMemory_94d8 {
  strings:
    $key_94d8 = { c3 aa [2] f1 88 [2] f7 bd [2] d9 bd [2] e6 a1 }

  condition:
    any of them
}