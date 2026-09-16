rule TTP_XOR_WriteProcessMemory_2bdd {
  strings:
    $key_2bdd = { 7c af [2] 4e 8d [2] 48 b8 [2] 66 b8 [2] 59 a4 }

  condition:
    any of them
}