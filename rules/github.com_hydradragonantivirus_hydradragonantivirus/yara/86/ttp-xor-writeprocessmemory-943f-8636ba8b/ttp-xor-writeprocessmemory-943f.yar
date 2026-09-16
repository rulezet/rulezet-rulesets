rule TTP_XOR_WriteProcessMemory_943f {
  strings:
    $key_943f = { c3 4d [2] f1 6f [2] f7 5a [2] d9 5a [2] e6 46 }

  condition:
    any of them
}