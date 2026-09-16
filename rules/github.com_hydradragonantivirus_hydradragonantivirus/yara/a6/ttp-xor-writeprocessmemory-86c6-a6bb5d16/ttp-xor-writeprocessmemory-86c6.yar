rule TTP_XOR_WriteProcessMemory_86c6 {
  strings:
    $key_86c6 = { d1 b4 [2] e3 96 [2] e5 a3 [2] cb a3 [2] f4 bf }

  condition:
    any of them
}