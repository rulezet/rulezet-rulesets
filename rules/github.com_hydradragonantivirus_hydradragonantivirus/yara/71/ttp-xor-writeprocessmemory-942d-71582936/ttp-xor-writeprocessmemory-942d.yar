rule TTP_XOR_WriteProcessMemory_942d {
  strings:
    $key_942d = { c3 5f [2] f1 7d [2] f7 48 [2] d9 48 [2] e6 54 }

  condition:
    any of them
}