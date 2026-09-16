rule TTP_XOR_WriteProcessMemory_82df {
  strings:
    $key_82df = { d5 ad [2] e7 8f [2] e1 ba [2] cf ba [2] f0 a6 }

  condition:
    any of them
}