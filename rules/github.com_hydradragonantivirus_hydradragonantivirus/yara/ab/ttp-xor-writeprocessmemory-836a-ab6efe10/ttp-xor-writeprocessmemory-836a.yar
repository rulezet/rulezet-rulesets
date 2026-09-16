rule TTP_XOR_WriteProcessMemory_836a {
  strings:
    $key_836a = { d4 18 [2] e6 3a [2] e0 0f [2] ce 0f [2] f1 13 }

  condition:
    any of them
}