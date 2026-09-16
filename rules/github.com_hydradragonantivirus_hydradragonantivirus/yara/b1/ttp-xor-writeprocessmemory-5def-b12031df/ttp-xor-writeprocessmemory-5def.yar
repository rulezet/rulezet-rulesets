rule TTP_XOR_WriteProcessMemory_5def {
  strings:
    $key_5def = { 0a 9d [2] 38 bf [2] 3e 8a [2] 10 8a [2] 2f 96 }

  condition:
    any of them
}