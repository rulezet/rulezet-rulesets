rule TTP_XOR_WriteProcessMemory_d895 {
  strings:
    $key_d895 = { 8f e7 [2] bd c5 [2] bb f0 [2] 95 f0 [2] aa ec }

  condition:
    any of them
}