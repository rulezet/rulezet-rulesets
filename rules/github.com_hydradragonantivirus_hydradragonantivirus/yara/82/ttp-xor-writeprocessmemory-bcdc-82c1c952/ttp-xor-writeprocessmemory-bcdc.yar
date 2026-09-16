rule TTP_XOR_WriteProcessMemory_bcdc {
  strings:
    $key_bcdc = { eb ae [2] d9 8c [2] df b9 [2] f1 b9 [2] ce a5 }

  condition:
    any of them
}