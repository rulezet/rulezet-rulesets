rule TTP_XOR_WriteProcessMemory_bc0a {
  strings:
    $key_bc0a = { eb 78 [2] d9 5a [2] df 6f [2] f1 6f [2] ce 73 }

  condition:
    any of them
}