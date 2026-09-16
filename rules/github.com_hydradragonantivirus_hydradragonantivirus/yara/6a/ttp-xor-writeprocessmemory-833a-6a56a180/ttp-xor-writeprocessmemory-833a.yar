rule TTP_XOR_WriteProcessMemory_833a {
  strings:
    $key_833a = { d4 48 [2] e6 6a [2] e0 5f [2] ce 5f [2] f1 43 }

  condition:
    any of them
}