rule TTP_XOR_WriteProcessMemory_acd8 {
  strings:
    $key_acd8 = { fb aa [2] c9 88 [2] cf bd [2] e1 bd [2] de a1 }

  condition:
    any of them
}