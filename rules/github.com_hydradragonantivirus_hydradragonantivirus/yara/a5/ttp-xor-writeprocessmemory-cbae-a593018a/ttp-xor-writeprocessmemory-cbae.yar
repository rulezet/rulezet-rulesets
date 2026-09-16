rule TTP_XOR_WriteProcessMemory_cbae {
  strings:
    $key_cbae = { 9c dc [2] ae fe [2] a8 cb [2] 86 cb [2] b9 d7 }

  condition:
    any of them
}