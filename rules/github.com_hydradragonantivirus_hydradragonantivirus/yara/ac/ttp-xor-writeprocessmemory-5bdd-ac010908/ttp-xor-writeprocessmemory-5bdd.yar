rule TTP_XOR_WriteProcessMemory_5bdd {
  strings:
    $key_5bdd = { 0c af [2] 3e 8d [2] 38 b8 [2] 16 b8 [2] 29 a4 }

  condition:
    any of them
}