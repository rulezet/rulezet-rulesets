rule TTP_XOR_WriteProcessMemory_6ada {
  strings:
    $key_6ada = { 3d a8 [2] 0f 8a [2] 09 bf [2] 27 bf [2] 18 a3 }

  condition:
    any of them
}