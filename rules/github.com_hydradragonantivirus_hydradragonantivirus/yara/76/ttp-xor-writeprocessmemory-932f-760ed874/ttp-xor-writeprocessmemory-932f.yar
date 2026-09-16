rule TTP_XOR_WriteProcessMemory_932f {
  strings:
    $key_932f = { c4 5d [2] f6 7f [2] f0 4a [2] de 4a [2] e1 56 }

  condition:
    any of them
}