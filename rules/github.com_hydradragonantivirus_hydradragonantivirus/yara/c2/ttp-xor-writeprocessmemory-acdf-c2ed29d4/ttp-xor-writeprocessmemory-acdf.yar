rule TTP_XOR_WriteProcessMemory_acdf {
  strings:
    $key_acdf = { fb ad [2] c9 8f [2] cf ba [2] e1 ba [2] de a6 }

  condition:
    any of them
}