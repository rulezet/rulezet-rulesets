rule TTP_XOR_WriteProcessMemory_932d {
  strings:
    $key_932d = { c4 5f [2] f6 7d [2] f0 48 [2] de 48 [2] e1 54 }

  condition:
    any of them
}