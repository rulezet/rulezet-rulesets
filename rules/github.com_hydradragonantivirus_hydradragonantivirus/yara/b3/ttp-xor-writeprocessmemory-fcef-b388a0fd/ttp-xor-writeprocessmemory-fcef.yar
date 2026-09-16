rule TTP_XOR_WriteProcessMemory_fcef {
  strings:
    $key_fcef = { ab 9d [2] 99 bf [2] 9f 8a [2] b1 8a [2] 8e 96 }

  condition:
    any of them
}