rule TTP_XOR_WriteProcessMemory_abe4 {
  strings:
    $key_abe4 = { fc 96 [2] ce b4 [2] c8 81 [2] e6 81 [2] d9 9d }

  condition:
    any of them
}