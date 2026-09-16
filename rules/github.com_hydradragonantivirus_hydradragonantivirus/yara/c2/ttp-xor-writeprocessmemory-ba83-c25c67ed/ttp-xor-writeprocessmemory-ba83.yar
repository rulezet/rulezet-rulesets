rule TTP_XOR_WriteProcessMemory_ba83 {
  strings:
    $key_ba83 = { ed f1 [2] df d3 [2] d9 e6 [2] f7 e6 [2] c8 fa }

  condition:
    any of them
}