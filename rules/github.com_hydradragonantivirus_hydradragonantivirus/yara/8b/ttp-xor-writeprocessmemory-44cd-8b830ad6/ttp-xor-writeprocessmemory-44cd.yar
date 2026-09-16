rule TTP_XOR_WriteProcessMemory_44cd {
  strings:
    $key_44cd = { 13 bf [2] 21 9d [2] 27 a8 [2] 09 a8 [2] 36 b4 }

  condition:
    any of them
}