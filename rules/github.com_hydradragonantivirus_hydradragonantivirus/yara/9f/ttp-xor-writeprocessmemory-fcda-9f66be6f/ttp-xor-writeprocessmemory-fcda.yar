rule TTP_XOR_WriteProcessMemory_fcda {
  strings:
    $key_fcda = { ab a8 [2] 99 8a [2] 9f bf [2] b1 bf [2] 8e a3 }

  condition:
    any of them
}