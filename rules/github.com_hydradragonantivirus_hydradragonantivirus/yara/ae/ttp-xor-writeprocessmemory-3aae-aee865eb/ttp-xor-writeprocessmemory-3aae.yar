rule TTP_XOR_WriteProcessMemory_3aae {
  strings:
    $key_3aae = { 6d dc [2] 5f fe [2] 59 cb [2] 77 cb [2] 48 d7 }

  condition:
    any of them
}