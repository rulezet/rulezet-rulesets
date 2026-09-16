rule TTP_XOR_WriteProcessMemory_bcb6 {
  strings:
    $key_bcb6 = { eb c4 [2] d9 e6 [2] df d3 [2] f1 d3 [2] ce cf }

  condition:
    any of them
}