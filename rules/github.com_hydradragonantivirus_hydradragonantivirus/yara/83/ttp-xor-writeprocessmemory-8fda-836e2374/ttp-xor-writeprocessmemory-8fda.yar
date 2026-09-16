rule TTP_XOR_WriteProcessMemory_8fda {
  strings:
    $key_8fda = { d8 a8 [2] ea 8a [2] ec bf [2] c2 bf [2] fd a3 }

  condition:
    any of them
}