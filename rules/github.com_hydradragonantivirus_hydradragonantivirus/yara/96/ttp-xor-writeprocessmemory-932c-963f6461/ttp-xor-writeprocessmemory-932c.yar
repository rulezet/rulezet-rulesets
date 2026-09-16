rule TTP_XOR_WriteProcessMemory_932c {
  strings:
    $key_932c = { c4 5e [2] f6 7c [2] f0 49 [2] de 49 [2] e1 55 }

  condition:
    any of them
}