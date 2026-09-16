rule TTP_XOR_WriteProcessMemory_941d {
  strings:
    $key_941d = { c3 6f [2] f1 4d [2] f7 78 [2] d9 78 [2] e6 64 }

  condition:
    any of them
}