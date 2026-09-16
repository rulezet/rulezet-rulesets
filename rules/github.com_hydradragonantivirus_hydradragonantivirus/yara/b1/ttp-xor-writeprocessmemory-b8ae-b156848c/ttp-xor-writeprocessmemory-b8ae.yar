rule TTP_XOR_WriteProcessMemory_b8ae {
  strings:
    $key_b8ae = { ef dc [2] dd fe [2] db cb [2] f5 cb [2] ca d7 }

  condition:
    any of them
}