rule TTP_XOR_WriteProcessMemory_bc1a {
  strings:
    $key_bc1a = { eb 68 [2] d9 4a [2] df 7f [2] f1 7f [2] ce 63 }

  condition:
    any of them
}