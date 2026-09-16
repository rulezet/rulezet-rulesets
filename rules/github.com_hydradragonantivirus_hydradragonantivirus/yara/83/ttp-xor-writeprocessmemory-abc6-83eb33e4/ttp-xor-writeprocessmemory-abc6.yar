rule TTP_XOR_WriteProcessMemory_abc6 {
  strings:
    $key_abc6 = { fc b4 [2] ce 96 [2] c8 a3 [2] e6 a3 [2] d9 bf }

  condition:
    any of them
}