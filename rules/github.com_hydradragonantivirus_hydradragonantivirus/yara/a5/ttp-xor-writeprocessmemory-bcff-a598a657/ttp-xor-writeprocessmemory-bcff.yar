rule TTP_XOR_WriteProcessMemory_bcff {
  strings:
    $key_bcff = { eb 8d [2] d9 af [2] df 9a [2] f1 9a [2] ce 86 }

  condition:
    any of them
}