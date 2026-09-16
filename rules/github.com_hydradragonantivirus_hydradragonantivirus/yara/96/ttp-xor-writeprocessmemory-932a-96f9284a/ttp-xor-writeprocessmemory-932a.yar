rule TTP_XOR_WriteProcessMemory_932a {
  strings:
    $key_932a = { c4 58 [2] f6 7a [2] f0 4f [2] de 4f [2] e1 53 }

  condition:
    any of them
}