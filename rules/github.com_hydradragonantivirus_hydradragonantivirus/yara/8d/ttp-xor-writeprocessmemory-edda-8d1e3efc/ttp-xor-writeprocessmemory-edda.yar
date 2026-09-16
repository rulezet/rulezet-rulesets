rule TTP_XOR_WriteProcessMemory_edda {
  strings:
    $key_edda = { ba a8 [2] 88 8a [2] 8e bf [2] a0 bf [2] 9f a3 }

  condition:
    any of them
}