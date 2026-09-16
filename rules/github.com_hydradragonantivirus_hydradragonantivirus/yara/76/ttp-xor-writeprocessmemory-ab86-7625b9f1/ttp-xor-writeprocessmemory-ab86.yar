rule TTP_XOR_WriteProcessMemory_ab86 {
  strings:
    $key_ab86 = { fc f4 [2] ce d6 [2] c8 e3 [2] e6 e3 [2] d9 ff }

  condition:
    any of them
}