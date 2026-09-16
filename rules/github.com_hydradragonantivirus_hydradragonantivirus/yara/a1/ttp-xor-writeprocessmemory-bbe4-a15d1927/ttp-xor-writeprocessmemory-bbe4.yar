rule TTP_XOR_WriteProcessMemory_bbe4 {
  strings:
    $key_bbe4 = { ec 96 [2] de b4 [2] d8 81 [2] f6 81 [2] c9 9d }

  condition:
    any of them
}