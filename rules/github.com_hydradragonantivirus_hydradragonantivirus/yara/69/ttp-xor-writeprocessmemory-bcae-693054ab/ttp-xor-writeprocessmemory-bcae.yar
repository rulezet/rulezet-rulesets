rule TTP_XOR_WriteProcessMemory_bcae {
  strings:
    $key_bcae = { eb dc [2] d9 fe [2] df cb [2] f1 cb [2] ce d7 }

  condition:
    any of them
}