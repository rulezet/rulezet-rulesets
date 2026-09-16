rule TTP_XOR_WriteProcessMemory_87ae {
  strings:
    $key_87ae = { d0 dc [2] e2 fe [2] e4 cb [2] ca cb [2] f5 d7 }

  condition:
    any of them
}