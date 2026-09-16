rule TTP_XOR_WriteProcessMemory_86cd {
  strings:
    $key_86cd = { d1 bf [2] e3 9d [2] e5 a8 [2] cb a8 [2] f4 b4 }

  condition:
    any of them
}