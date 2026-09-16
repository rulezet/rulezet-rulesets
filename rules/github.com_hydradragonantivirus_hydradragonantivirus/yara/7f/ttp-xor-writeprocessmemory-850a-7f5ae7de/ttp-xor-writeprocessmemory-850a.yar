rule TTP_XOR_WriteProcessMemory_850a {
  strings:
    $key_850a = { d2 78 [2] e0 5a [2] e6 6f [2] c8 6f [2] f7 73 }

  condition:
    any of them
}