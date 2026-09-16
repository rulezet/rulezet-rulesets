rule TTP_XOR_WriteProcessMemory_9eda {
  strings:
    $key_9eda = { c9 a8 [2] fb 8a [2] fd bf [2] d3 bf [2] ec a3 }

  condition:
    any of them
}