rule TTP_XOR_WriteProcessMemory_bc8d {
  strings:
    $key_bc8d = { eb ff [2] d9 dd [2] df e8 [2] f1 e8 [2] ce f4 }

  condition:
    any of them
}