rule TTP_XOR_WriteProcessMemory_bc2f {
  strings:
    $key_bc2f = { eb 5d [2] d9 7f [2] df 4a [2] f1 4a [2] ce 56 }

  condition:
    any of them
}