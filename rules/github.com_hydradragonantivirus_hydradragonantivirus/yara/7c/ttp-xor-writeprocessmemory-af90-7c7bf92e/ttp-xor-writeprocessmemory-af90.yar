rule TTP_XOR_WriteProcessMemory_af90 {
  strings:
    $key_af90 = { f8 e2 [2] ca c0 [2] cc f5 [2] e2 f5 [2] dd e9 }

  condition:
    any of them
}