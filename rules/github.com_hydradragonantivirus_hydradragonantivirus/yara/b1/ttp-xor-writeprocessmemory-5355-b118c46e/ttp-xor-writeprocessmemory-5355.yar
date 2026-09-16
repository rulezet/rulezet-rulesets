rule TTP_XOR_WriteProcessMemory_5355 {
  strings:
    $key_5355 = { 04 27 [2] 36 05 [2] 30 30 [2] 1e 30 [2] 21 2c }

  condition:
    any of them
}