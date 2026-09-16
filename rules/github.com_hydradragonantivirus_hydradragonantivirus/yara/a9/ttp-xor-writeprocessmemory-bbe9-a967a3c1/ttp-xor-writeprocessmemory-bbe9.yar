rule TTP_XOR_WriteProcessMemory_bbe9 {
  strings:
    $key_bbe9 = { ec 9b [2] de b9 [2] d8 8c [2] f6 8c [2] c9 90 }

  condition:
    any of them
}