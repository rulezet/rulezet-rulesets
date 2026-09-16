rule TTP_XOR_WriteProcessMemory_add8 {
  strings:
    $key_add8 = { fa aa [2] c8 88 [2] ce bd [2] e0 bd [2] df a1 }

  condition:
    any of them
}