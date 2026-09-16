rule TTP_XOR_WriteProcessMemory_ce97 {
  strings:
    $key_ce97 = { 99 e5 [2] ab c7 [2] ad f2 [2] 83 f2 [2] bc ee }

  condition:
    any of them
}